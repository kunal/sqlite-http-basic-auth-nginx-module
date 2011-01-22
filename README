Name
====

sqlite-http-basic-auth-nginx-module - Sqlite based basic authentication for Nginx

Installation
============

1. Install sqlite3 into your system.

1. Download the latest version of the release tarball of this module from
sqlite-http-basic-auth-nginx-module [file list](http://github.com/kunal/sqlite-http-basic-auth-nginx-module/downloads).

1. Grab the nginx source code from [nginx.net](http://nginx.net/), for example,
the version 0.8.54 (see nginx compatibility), and then build the source with
this module:

        $ wget 'http://sysoev.ru/nginx/nginx-0.8.54.tar.gz'
        $ tar -xzvf nginx-0.8.54.tar.gz
        $ cd nginx-0.8.54/

        # Here we assume you would install you nginx under /opt/nginx/.
        $ ./configure --prefix=/opt/nginx \
            --add-module=/path/to/sqlite-http-basic-auth-nginx-module 

        $ make 
        $ make install

Usage
=====

Add the following to nginx.conf:

        location / {
            auth_sqlite_basic "Restricted Sqlite";
            auth_sqlite_basic_database_file  /home/kunal/nginx/db/sqlite_db; # Sqlite DB file
            auth_sqlite_basic_database_table  auth_table; # Sqlite DB table
            auth_sqlite_basic_table_user_column  user; # User column
            auth_sqlite_basic_table_passwd_column  password; # Password column
            root   html;
            index  index.html index.htm;
        }


Compatibility
=============

The following versions of Nginx should work with this module:

*   0.8.x (last tested: 0.8.54)

TODO
====

* Support encrypted passwords
* Support for "where" conditions

Copyright & License
===================

    This module is licenced under the BSD license.

    Copyright (C) 2011 by Kunal P.Bharati <kunalbharati@gmail.com>.

    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

        * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

        * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
