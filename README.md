Description
===========

Module adds support of *non-blocking* sending `error_log` and `access_log`
through UDP socket in syslog format.


Compatibility
=============

This module was tested with nginx 1.2.4.


Installation
============

    $ cd nginx/
    $ git clone git://github.com/seletskiy/nginx-syslog-module.git
    $ ./configure --add-module=nginx-syslog-module
    $ make
    $ make install


Usage
=====

Directives
----------

At this moment, module provides only two directives: `syslog_target` and
`syslog_map`.

### syslog_target ###

**syntax:** `syslog_target name { ... }`  
**default:** `none`  
**context:** `http`

Defines new syslog target with specified name (name will be used in `syslog_map`).
*None* of error and access logs will be duplicated to servers, described
in this section, if directive `syslog_map` is not specified.

`local6` will be used as syslog facility.

`info` severity will be used for access log entries.

This section can contains set of nested directives:

1. `host[:port]`  
   This directive is *required*.  
   Describes one UDP endpoint. Default port is `514`.
   You can specify one or more target servers to send to.

### syslog_map ###

**syntax:** `syslog_map type target[ log_fmt]`  
**default:** `none`  
**context:** `http`, `server`, `location`, `if`

Specifies kind of logs that should be duplicated to syslog.
Possible types: `error`, `access`.

So, `syslog_map access blabla` will duplicate all access logs to `blabla`
syslog target.

`log_fmt` can be used to specify custom log format. This feature works only
for `access` type logs:

    log_format my_format "$request_time $status";
    syslog_map access group_a my_format;

Consequence calls to `syslog_map` will overwrite previous calls with same `type`
parameter:

    syslog_map error group_a;
    syslog_map error group_b; # all errors will be sent to group_b, not group_a


Examples
--------

Send all error logs to `localhost:1058` and `syslog.local:514`,
access logs (except those contains `bla` in uri) to `syslog-access.ngs.local:1234`
and access logs from virtual server `localhost:8010` to `syslog-all.ngs.local:1234`.
All requests to uri `bla` on server `localhost:8010` will be logged to
`syslog-bla.ngs.local`.

    http {
        syslog_target group_a {
            localhost:1058;
            syslog.local;
        }

        syslog_target group_b {
            syslog-access.ngs.local:1234;
        }

        syslog_target group_c {
            syslog-all.ngs.local:1234;
        }

        syslog_target group_d {
            syslog-bla.ngs.local;
        }

        syslog_map error  group_a;
        syslog_map access group_b;

        server {
            server_name localhost;
            listen 8010;
            # all access logs from this server will be sent to `group_c`,
            # not to `group_b` (except those contains `bla` in request)
            syslog_map access group_c;

            if ($uri ~ bla) {
                syslog_map access group_d;
            }
        }

        server {
            server_name localhost;
            listen 8015;
            # all access logs from this server will be sent to `group_b`
        }
    }


What's next?
============

Directives:

1. `syslog_facility` for controlling facility;
2. `syslog_target/facility` for controlling facility per target;
3. `error_log syslog://` and `access_log syslog://` protocols.

Authors
=======

First version and inspiration was taken from
https://github.com/vkholodkov/nginx-syslog-module, but current version
is entirely rewritten and does not contain any common code.

Developer and maintainer: https://github.com/seletskiy
