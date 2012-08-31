Description
===========

Module adds support of sending `error_log` and `access_log`
through UDP socket in syslog format.


Compatibility
=============

This module and patch was tested with nginx 0.7.68 and 1.2.0.


Installation
============

*Warning:* module requires patch (look for nginx-*.patch file)
has been installed. Patch is required because it is not possible to duplicate
error_logs without it.

    $ cd nginx/
    $ git clone git://github.com/seletskiy/nginx-syslog-module.git
    $ patch -p1 < nginx-syslog-module/nginx-0.7.68.patch
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

Defines new syslog target with specified name (doesn't means anything for now).  
*None* of error and access logs will be duplicated to servers, described
in this section, if directive `syslog_map` is not specified.

`local6` will be used as syslog facility.

`info` severity will be used for access log entries.

This section can contains set of nested directives:

1. `host[:port]`  
   This directive is *required*.  
   Describes one UDP endpoint. Default port is `514`.

### syslog_map ###

**syntax:** `syslog_map type target`
**default:** `none`
**context:** `http`

Specifies what kind of logs should be duplicated to syslog.
Possible types: `all`, `error`, `access`.

So, `syslog_map access blabla` will duplicate all access logs to `blabla`
syslog target.


Examples
--------

Send all error logs to `localhost:1058` and `syslog.local:514`,
access logs to `syslog-access.ngs.local:1234` and all logs (error and access)
to `syslog-all.ngs.local:1234`.

    http {
        server {
            server_name localhost;
            listen 8010;
        }

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

        syslog_map error  group_a;
        syslog_map access group_b;
        syslog_map all    group_c;
    }


What's next?
============

Directives:

1. `syslog_facility` for controlling facility;
2. `syslog_target/facility` for controlling facility per target;
3. `error_log syslog://` and `access_log syslog://` protocols.
