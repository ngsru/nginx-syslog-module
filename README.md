Description
===========

Module adds support of sending `error_log` and `access_log`
through UDP socket in syslog format.


Installation
============

*Warning:* module requires patch (look for nginx-*.patch file)
has been installed.

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

At this moment, module provides only one directive: `syslog_target`.

### syslog_target ###

**syntax:** `syslog_target name { ... }`  
**default:** `none`  
**context:** `http`

Defines new syslog target with specified name (doesn't means anything for now).  
*All* error and access logs will be duplicated to servers, described
in this section.

`local6` will be used as syslog facility.

`info` severity will be used for access log entries.

This section can contains set of nested directives:

1. `host[:port]`  
   This directive is *required*.  
   Describes one UDP endpoint. Default port is `514`.

Examples
--------

Send all access and error logs to `localhost:1058` and `syslog.local:514` hosts.

    http {
        server {
            server_name localhost;
            listen 8010;
        }

        syslog_target global {
            localhost:1058;
            syslog.local;
        }
    }


What's next?
============

Directives:

1. `syslog_facility` for controlling facility;
2. `syslog_target/facility` for controlling facility per target;
3. `syslog_duplicate` for disabling duplicating all described logs;
4. `error_log syslog://` and `access_log syslog://` protocols.
