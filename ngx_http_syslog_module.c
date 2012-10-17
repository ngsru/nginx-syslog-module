
/*
 * Copyright (C) 2012 Seletskiy Stanislav <s.seletskiy@gmail.com>
 * Copyright (C) 2010 Valery Kholodkov
 *
 * NOTE: Some small fragments have been copied from original nginx log module due to exports problem.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <syslog.h>


/*
 * module specific constants
 */

#define NGX_SYSLOG_POOL_SIZE          16384      /* inital pool size for module (prealloc) */
#define NGX_SYSLOG_TARGETS_COUNT      8          /* initial targets count (prealloc) */
#define NGX_SYSLOG_MAP_SIZE           2          /* initial map size (prealloc) */
#define NGX_SYSLOG_CONNECTIONS_COUNT  8          /* initial connections count (prealloc) */
#define NGX_SYSLOG_DEFAULT_PORT       514        /* default UDP syslog port */
#define NGX_SYSLOG_DEFAULT_FACILITY   LOG_LOCAL6 /* default logging facility */
#define NGX_SYSLOG_DEFAULT_TAG        "nginx"    /* default syslog tag */
#define NGX_SYSLOG_BUFFER_SIZE        16384      /* max log line size */


/*
 * module specific structures
 */

typedef enum {
    NGX_HTTP_SYSLOG_SOURCE_UNDEF,
    NGX_HTTP_SYSLOG_SOURCE_ALL,
    NGX_HTTP_SYSLOG_SOURCE_ERROR,
    NGX_HTTP_SYSLOG_SOURCE_ACCESS
} ngx_http_syslog_source_e;

/* desribes confuguration of module */
typedef struct {
    ngx_array_t                 *targets; /* array of ngx_http_syslog_target_t */
    ngx_array_t                 *map;     /* array of ngx_http_syslog_mapping_t */
} ngx_http_syslog_main_conf_t;

/* describes one named target. can contain many connections to different
   udp servers */
typedef struct {
    ngx_str_t                    name;        /* name of target (specified in directive syslog_target) */
    ngx_array_t                 *connections; /* array of ngx_http_syslog_connection_t */
} ngx_http_syslog_target_t;

/* describes syslog mapping (source of log messages -> target of log messages) */
typedef struct {
    ngx_http_syslog_source_e     source;
    ngx_http_syslog_target_t    *target;
} ngx_http_syslog_mapping_t;

/* describes on connection to one server */
typedef struct {
    ngx_udp_connection_t        *udp;
} ngx_http_syslog_connection_t;

/* describes context for module. used in some context aware
   functions */
typedef struct {
    ngx_http_syslog_main_conf_t *conf;
    ngx_http_syslog_target_t    *target;
    ngx_int_t                    depth;
    ngx_pool_t                  *pool;   /* permanent pool */
    ngx_str_t                    buffer; /* buffer for line operations */
    ngx_http_request_t          *request;
} ngx_http_syslog_ctx_t;


/*
 * externals
 */

/* link to ngx_udp_connect function (declared in ngx_resolver.c) */
ngx_int_t ngx_udp_connect(ngx_udp_connection_t *uc);


/*
 * nginx specific module handlers declaration
 */

static ngx_int_t ngx_http_syslog_init(ngx_conf_t *cf);
static void *ngx_http_syslog_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_syslog_create_loc_conf(ngx_conf_t *cf);
static void *ngx_http_syslog_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_syslog_init_conf(ngx_conf_t *cf);
static char *ngx_http_syslog_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_syslog_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_syslog_exit_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_syslog_save_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_syslog_drop_request_handler(ngx_http_request_t *r);


/*
 * module specific functions declaration
 */

/* tries to connect to specified server */
static ngx_int_t ngx_http_syslog_connect(ngx_http_syslog_connection_t *uc);

/* init group of servers (target), connecting to each of this */
static ngx_int_t ngx_http_syslog_init_target(ngx_pool_t *pool, ngx_http_syslog_target_t *target);

/* handler for syslog_target directive */
static char *ngx_http_syslog_target_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);

/* handler for syslog_map directive */
static char *ngx_http_syslog_map_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);

/* handler for syslog_target/host[:port] directive */
static char *ngx_http_syslog_target(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);

/* callback for error_log/access_log write action */
#if defined NGX_HTTP_SYSLOG_PATCH
static void ngx_http_syslog_error_handler(ngx_uint_t source, void *data, ngx_uint_t level, u_char *buf, size_t len);
#endif

/* makes correct formatted syslog log line and sends it to specified group of servers (target) */
static void ngx_http_syslog_send(ngx_http_syslog_ctx_t *ctx, ngx_http_syslog_target_t *target,
    ngx_uint_t level, u_char *buf, ngx_int_t len);

/* low level function: send buffer to specified group of servers (target) */
static void ngx_http_syslog_send_all(ngx_pool_t *pool, ngx_http_syslog_target_t *target,
    u_char *buf, ngx_int_t len);

/* low level function: send buffer to specified connection (on server) */
static void ngx_http_syslog_send_one(ngx_http_syslog_connection_t *connection,
    u_char *buf, ngx_int_t len);

/* callback for connection cleanup */
static void ngx_http_syslog_close_connection(void *data);

/* dummy callback for event read handler */
static void ngx_http_syslog_udp_read_handler(ngx_event_t *ev);

/* adds mapping or update existing */
static void
ngx_http_syslog_add_mapping(ngx_array_t *map, ngx_http_syslog_source_e source,
    ngx_http_syslog_target_t *target, int update);

/*
 * nginx module declaration
 */

static ngx_command_t  ngx_http_syslog_commands[] = {
    { ngx_string("syslog_target"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_syslog_target_block,
      0,
      0,
      NULL },

    { ngx_string("syslog_map"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2,
      ngx_http_syslog_map_cmd,
      0,
      0,
      NULL },

    /* TODO:
       1. syslog_facility
       2. syslog_target/facility */

      ngx_null_command
};

static ngx_http_module_t  ngx_http_syslog_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_syslog_init,                  /* postconfiguration */

    ngx_http_syslog_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_syslog_create_srv_conf,       /* create server configuration */
    ngx_http_syslog_merge_srv_conf,        /* merge server configuration */

    ngx_http_syslog_create_loc_conf,       /* create location configration */
    ngx_http_syslog_merge_loc_conf         /* merge location configration */
};

extern ngx_module_t  ngx_http_log_module;

ngx_module_t  ngx_http_syslog_module = {
    NGX_MODULE_V1,
    &ngx_http_syslog_module_ctx,           /* module context */
    ngx_http_syslog_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_syslog_exit_process,          /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};



/*
 * nginx specific module handlers implementation
 */

static void *
ngx_http_syslog_create_main_conf(ngx_conf_t *cf)
{
    return ngx_http_syslog_init_conf(cf);
}

static void *
ngx_http_syslog_create_srv_conf(ngx_conf_t *cf)
{
    return ngx_http_syslog_init_conf(cf);
}

static void *
ngx_http_syslog_create_loc_conf(ngx_conf_t *cf)
{
    return ngx_http_syslog_init_conf(cf);
}

static void *
ngx_http_syslog_init_conf(ngx_conf_t *cf)
{
    ngx_http_syslog_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_syslog_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->targets = ngx_array_create(cf->pool,
        NGX_SYSLOG_TARGETS_COUNT,
        sizeof(ngx_http_syslog_target_t));

    conf->map = ngx_array_create(cf->pool,
        NGX_SYSLOG_MAP_SIZE,
        sizeof(ngx_http_syslog_mapping_t));

    return conf;
}

static char *
ngx_http_syslog_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_syslog_main_conf_t *prev = parent;
    ngx_http_syslog_main_conf_t *conf = child;
    ngx_http_syslog_mapping_t   *prev_mapping;
    unsigned int                 i;


    for (i = 0; i < prev->map->nelts; i++) {
        prev_mapping = &((ngx_http_syslog_mapping_t*)prev->map->elts)[i];

        ngx_http_syslog_add_mapping(conf->map,
            prev_mapping->source, prev_mapping->target, 0);
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_syslog_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return ngx_http_syslog_merge_srv_conf(cf, parent, child);
}

static ngx_int_t
ngx_http_syslog_save_request_handler(ngx_http_request_t *r)
{
    ngx_http_syslog_ctx_t       *ctx;

    ctx = r->connection->log->prewrite.data;

    ctx->request = r;

    return NGX_OK;
}

static ngx_int_t
ngx_http_syslog_drop_request_handler(ngx_http_request_t *r)
{
    ngx_http_syslog_ctx_t       *ctx;

    ctx = r->connection->log->prewrite.data;

    ctx->request = NULL;

    return NGX_OK;
}

static ngx_int_t
ngx_http_syslog_init(ngx_conf_t *cf)
{
    ngx_http_syslog_main_conf_t *conf;
    ngx_http_syslog_ctx_t       *ctx;
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_syslog_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_syslog_save_request_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_syslog_drop_request_handler;

    /* creating context for context aware error handler */
#if defined nginx_version && nginx_version >= 7003
    ctx = ngx_pnalloc(cf->pool, sizeof(ngx_http_syslog_ctx_t));
#else
    ctx = ngx_palloc(cf->pool, sizeof(ngx_http_syslog_ctx_t));
#endif

    ctx->conf = conf;
    ctx->pool = cf->pool;
    ctx->buffer.len = NGX_SYSLOG_BUFFER_SIZE;
#if defined nginx_version && nginx_version >= 7003
    ctx->buffer.data = ngx_pnalloc(ctx->pool, sizeof(u_char) * NGX_SYSLOG_BUFFER_SIZE);
#else
    ctx->buffer.data = ngx_palloc(ctx->pool, sizeof(u_char) * NGX_SYSLOG_BUFFER_SIZE);
#endif
    ctx->depth = 0;

#if defined NGX_HTTP_SYSLOG_PATCH
    cf->cycle->new_log.prewrite.data = ctx;
    cf->cycle->new_log.prewrite.handler = ngx_http_syslog_error_handler;
#else
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "nginx is not patched to support ngx_http_syslog_module, module will have no effect");
#endif

    return NGX_OK;
}

static void ngx_http_syslog_exit_process(ngx_cycle_t *cycle)
{
#if defined NGX_HTTP_SYSLOG_PATCH
    cycle->log->prewrite.data = NULL;
    cycle->log->prewrite.handler = NULL;
#endif
}


/*
 * module specific functions implementation
 */

/* global error handler. called when error_log or access_log tries to write
   message to file */
#if defined NGX_HTTP_SYSLOG_PATCH
static void
ngx_http_syslog_error_handler(ngx_uint_t source, void *data, ngx_uint_t level, u_char *buf, size_t len)
{
    ngx_http_syslog_main_conf_t *conf;
    ngx_http_syslog_ctx_t       *ctx;
    ngx_http_syslog_mapping_t   *map;
    ngx_http_syslog_source_e     item_source;
    unsigned                     i;

    ctx = data;

    if (ctx->request) {
        conf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_syslog_module);
    } else {
        conf = ctx->conf;
    }

    /* dirty hack to check that all confuguration ready
       and UDP socket can be opened.
       dunno how to check it correctly */
    if (ngx_cycle->free_connections == 0) {
        return;
    }

    /* prevent recursion */
    if (ctx->depth > 1) {
        return;
    }

    if (source == 0) {
        item_source = NGX_HTTP_SYSLOG_SOURCE_ERROR;
    } else if (source == 1) {
        item_source = NGX_HTTP_SYSLOG_SOURCE_ACCESS;
    } else {
        item_source = NGX_HTTP_SYSLOG_SOURCE_UNDEF;
    }

    ctx->depth++;

    map = conf->map->elts;
    for (i = 0; i < conf->map->nelts; i++) {
        if (map[i].source == item_source || map[i].source == NGX_HTTP_SYSLOG_SOURCE_ALL) {
            ngx_http_syslog_send(ctx, map[i].target, level, buf, len);
        }
    }

    ctx->depth--;
}
#endif

/* handler for syslog_target directive */
static char *
ngx_http_syslog_target_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    ngx_http_syslog_main_conf_t *conf;
    ngx_http_syslog_target_t    *target;
    ngx_pool_t                  *pool;
    ngx_conf_t                   old_cf;
    ngx_str_t                   *value;
    ngx_http_syslog_ctx_t        ctx;

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_syslog_module);

    /* parsing 'syslog_target _name_ {' part */
    value = cf->args->elts;
    target = ngx_array_push(conf->targets);
    target->name = value[1];
    target->connections = ngx_array_create(cf->pool,
        NGX_SYSLOG_CONNECTIONS_COUNT,
        sizeof(ngx_http_syslog_connection_t));

    /* preparing context for parsing directive block */
    ctx.target = target;
    ctx.conf = conf;
    ctx.pool = cf->pool;

    old_cf = *cf;

    /* creating temporary pool */
    pool = ngx_create_pool(NGX_SYSLOG_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return NGX_CONF_ERROR;
    }

    cf->pool = pool;
    cf->handler = ngx_http_syslog_target;
    cf->handler_conf = dummy;
    cf->ctx = &ctx;

    /* dig into syslog_target {...} block */
    if (ngx_conf_parse(cf, NULL) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    *cf = old_cf;

    if (!target->connections->nelts) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "syslog_target must have at least one endpoint");

        return NGX_CONF_ERROR;
    }

    /* destroying temporary pool */
    ngx_destroy_pool(pool);

    return NGX_OK;
}

/* handler for syslog_map directive */
static char *ngx_http_syslog_map_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    ngx_http_syslog_main_conf_t *conf;
    ngx_http_syslog_main_conf_t *smcf;
    ngx_str_t                   *args;
    ngx_http_syslog_target_t    *target;
    ngx_http_syslog_source_e     source;
    unsigned int                 i;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_syslog_module);
    conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_syslog_module);

    args = cf->args->elts;

    for (i = 0; i < smcf->targets->nelts; i++) {
        target = &((ngx_http_syslog_target_t*)smcf->targets->elts)[i];

        if (ngx_strcmp(target->name.data, args[2].data) == 0) {
            break;
        }

        target = NULL;
    }

    if (!target) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "syslog_map got unknown target name");

        return NGX_CONF_ERROR;
    }

    source = NGX_HTTP_SYSLOG_SOURCE_UNDEF;
    if (ngx_strcmp("access", args[1].data) == 0) {
        source = NGX_HTTP_SYSLOG_SOURCE_ACCESS;
    } else if (ngx_strcmp("error", args[1].data) == 0) {
        source = NGX_HTTP_SYSLOG_SOURCE_ERROR;
    }

    if (source == NGX_HTTP_SYSLOG_SOURCE_UNDEF) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "syslog_map got unknown source name");

        return NGX_CONF_ERROR;
    }

    ngx_http_syslog_add_mapping(conf->map, source, target, 1);

    return NGX_OK;
}

/* handler for inner directives of syslog_target {...} block.
   TODO: add handling of other useful directives (e.g. facility)*/
static char *
ngx_http_syslog_target(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    ngx_http_syslog_connection_t *connection;
    ngx_http_syslog_target_t     *target;
    ngx_udp_connection_t         *udp;
    ngx_http_syslog_ctx_t        *ctx;
    ngx_str_t                    *value;
    ngx_url_t                     u;

    ctx = cf->ctx;

    /* note:
       ctx->pool is permanent pool
       cf->pool  is temporary pool */

    /* trying to parse inner directive as hostname */
    value = cf->args->elts;
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[0];
    u.default_port = NGX_SYSLOG_DEFAULT_PORT;
    if (ngx_parse_url(ctx->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s in syslog_target: %V", u.err, &value[0]);

            return NGX_CONF_ERROR;
        }
    }

    target = ctx->target;

    connection = ngx_array_push(target->connections);
    if (connection == NULL) {
        return NGX_CONF_ERROR;
    }

#if defined nginx_version && nginx_version >= 7003
    udp = ngx_pnalloc(ctx->pool, sizeof(ngx_udp_connection_t));
#else
    udp = ngx_palloc(ctx->pool, sizeof(ngx_udp_connection_t));
#endif

    /* TODO: parse url in temporary pool and copy only necessary socket data */
    ngx_memzero(udp, sizeof(ngx_http_syslog_connection_t));
    udp->sockaddr = u.addrs[0].sockaddr;
    udp->socklen = u.addrs[0].socklen;
    udp->server.len = u.addrs[0].name.len;
    udp->server = u.addrs[0].name; //ngx_pstrdup(ctx->perm_pool, &u.addrs[0].name);
#if defined nginx_version && ( nginx_version >= 7054 && nginx_version < 8032 )
    udp->log = &cf->cycle->new_log;
#else
    udp->log = cf->cycle->new_log;
#if defined nginx_version && nginx_version >= 8032
    udp->log.handler = NULL;
    udp->log.data = NULL;
    udp->log.action = "logging";
#endif
#endif

    connection->udp = udp;

    return NGX_CONF_OK;
}

/* tries to connect to specified server */
static ngx_int_t
ngx_http_syslog_connect(ngx_http_syslog_connection_t *connection)
{
    ngx_udp_connection_t *udp;

    udp = connection->udp;
    if (ngx_udp_connect(udp) != NGX_OK) {
       if (udp->connection != NULL) {
           ngx_free_connection(udp->connection);
           udp->connection = NULL;
       }

       return NGX_ERROR;
    }

    return NGX_OK;
}

/* init group of servers (target), connecting to each of this */
static ngx_int_t
ngx_http_syslog_init_target(ngx_pool_t *pool, ngx_http_syslog_target_t *target)
{
    ngx_http_syslog_connection_t *connections;
    ngx_http_syslog_connection_t *connection;
    ngx_http_syslog_connection_t *clnconn;
    ngx_pool_cleanup_t           *cln;
    unsigned                      i;

    connections = target->connections->elts;
    for (i = 0; i < target->connections->nelts; i++) {
        connection = &connections[i];
        if (connection->udp->connection != NULL) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, connection->udp->log, 0,
            "syslog connecting to server %V", &connection->udp->server);

        if (ngx_http_syslog_connect(connection) != NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, connection->udp->log, 0,
                "syslog couldn't connect to server %V", &connection->udp->server);

            /* TODO: return NGX_ERROR? */
        }

        cln = ngx_pool_cleanup_add(pool, sizeof(ngx_http_syslog_connection_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }

        clnconn = cln->data;
        clnconn->udp = connection->udp;
        cln->handler = ngx_http_syslog_close_connection;
    }

    return NGX_OK;
}

/* makes correct formatted syslog log line and
   sends it to specified group of servers (target) */
static void
ngx_http_syslog_send(ngx_http_syslog_ctx_t *ctx, ngx_http_syslog_target_t *target,
    ngx_uint_t level, u_char *buf, ngx_int_t len)
{
    ngx_tm_t     tm;
    u_char      *line;
    ngx_str_t    tag, msg;
    ngx_uint_t   pri;
    size_t       line_len;
    time_t       time;
    static char *months[] = {
        "Jan", "Feb", "Mar",
        "Apr", "May", "Jun",
        "Jul", "Aug", "Sep",
        "Oct", "Nov", "Dec"
    };

    time = ngx_time();
    /* TODO: ngx_gmtime? */
    ngx_localtime(time, &tm);

    tag.data = (u_char*)NGX_SYSLOG_DEFAULT_TAG;
    tag.len = sizeof(NGX_SYSLOG_DEFAULT_TAG) - 1;

    /* TODO: not hardcoded priority */
    pri = NGX_SYSLOG_DEFAULT_FACILITY + level;

    line = ctx->buffer.data;
    line_len =
        sizeof("<255>") - 1 +           /* priority */
        sizeof("Jan 31 00:00:00") - 1 + /* date */
        1 +                             /* space */
        ngx_cycle->hostname.len +       /* hostname */
        1 +                             /* space */
        tag.len +                       /* tag */
        1 +                             /* space */
        1 +                             /* colon */
        len;                            /* message */
    if (line_len > ctx->buffer.len) {
        line_len = ctx->buffer.len;
    }

    msg.len = len;
    msg.data = buf;

    ngx_snprintf(
        line, line_len,
        "<%ui>"           /* priority */
        "%s "             /* month */
        "%2d "            /* day */
        "%02d:%02d:%02d " /* HH:MM:SS */
        "%V %V: %V",      /* host tag: message */
        pri, months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
        tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec,
        &ngx_cycle->hostname, &tag, &msg);

    ngx_http_syslog_send_all(ctx->pool, target, line, line_len);
}

/* low level function: send buffer to specified group of servers (target) */
static void
ngx_http_syslog_send_all(ngx_pool_t *pool, ngx_http_syslog_target_t *target,
    u_char *buf, ngx_int_t len)
{
    ngx_http_syslog_connection_t *connections;
    unsigned                      i;

    if (ngx_http_syslog_init_target(pool, target) != NGX_OK) {
        return;
    }

    connections = target->connections->elts;

    for (i = 0; i < target->connections->nelts; i++) {
        ngx_http_syslog_send_one(&connections[i], buf, len);
    }
}

/* low level function: send buffer to specified connection (on server) */
static void
ngx_http_syslog_send_one(ngx_http_syslog_connection_t *connection,
    u_char *buf, ngx_int_t len)
{
    ngx_udp_connection_t *uc;
    ssize_t               sent;

    uc = connection->udp;

    if (uc == NULL) {
        return;
    }

    if (uc->connection == NULL) {
        return;
    }

    /* works well (7068) */
    uc->connection->data = NULL;
    uc->connection->read->handler = ngx_http_syslog_udp_read_handler;
    uc->connection->read->resolver = 0;

    sent = ngx_send(uc->connection, buf, len);
    if (sent == -1) {
#if defined nginx_version && nginx_version >= 8032
        ngx_log_error(NGX_LOG_CRIT, &uc->log, 0, "syslog send() failed (%V)", &uc->server);
#else
        ngx_log_error(NGX_LOG_CRIT, uc->log, 0, "syslog send() failed (%V)", &uc->server);
#endif
        return;
    }

    if ((size_t) sent != (size_t) len) {
#if defined nginx_version && nginx_version >= 8032
        ngx_log_error(NGX_LOG_CRIT, &uc->log, 0, "syslog send() incomplete (%V)", &uc->server);
#else
        ngx_log_error(NGX_LOG_CRIT, uc->log, 0, "syslog send() incomplete (%V)", &uc->server);
#endif
        return;
    }
}

/* callback for connection cleanup */
static void
ngx_http_syslog_close_connection(void *data)
{
    ngx_http_syslog_connection_t *connection;

    connection = data;

    ngx_close_connection(connection->udp->connection);
}

static void
ngx_http_syslog_udp_read_handler(ngx_event_t *ev)
{
    // noop
}

/* adds mapping or update existing */
static void
ngx_http_syslog_add_mapping(ngx_array_t *map, ngx_http_syslog_source_e source,
    ngx_http_syslog_target_t *target,
    int update)
{
    ngx_http_syslog_mapping_t *elem;
    unsigned int               i;

    for (i = 0; i < map->nelts; i++) {
        elem = &((ngx_http_syslog_mapping_t*)map->elts)[i];

        if (elem->source == source) {
            if (update) {
                elem->target = target;
            }
            return;
        }
    }

    elem = ngx_array_push(map);
    elem->source = source;
    elem->target = target;
}
