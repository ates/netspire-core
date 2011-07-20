Netspire: RADIUS server and NetFlow collector
=============================================

Netspire is designed to make a simple base for writing ISP billing software. In current state it includes:

* [RADIUS](http://en.wikipedia.org/wiki/RADIUS) server compliant with [RFC 2138](http://www.ietf.org/rfc/rfc2138.txt) and [RFC 2139](http://www.ietf.org/rfc/rfc2138.txt) with support for unlimited number of NAS'es
* [Netflow](http://en.wikipedia.org/wiki/Netflow) collector with v5 and v9 protocol versions support
* Modular structure very similar to [ProcessOne](http://www.process-one.net)'s nice [ejabberd](http://www.ejabberd.im)

This is an alpha software, so be ready for possible API changes.

Dependencies
------------

Netspire is written in [Erlang](http://en.wikipedia.org/wiki/Erlang_%28programming_language%29) and requires [Erlang/OTP](http://www.erlang.org) platform to be installed.

As per the Wikipedia:

>Erlang is a general-purpose concurrent programming language and runtime system. It was designed by Ericsson to support distributed, fault-tolerant, soft-real-time, non-stop applications.

Installation
------------

Currently Netspire runs on Linux, BSD based systems and Mac OS X. Clone this repo or download an archive, then execute:

    $ autoconf

    $ ./configure

    $ make (On BSD systems you must use 'gmake' instead 'make')

    $ make install

Future plans
------------

There are serious plans to make a billing system on top of this core with [PostgreSQL](http://www.postgresql.org) backend as well as awesome [Apache CouchDB](http://couchdb.apache.org) with Web-based admin interface. Currently all these modules are under development.

Contribution
------------

Feel free to report issues and suggestions, patches are also welcome.

Licensing
---------

All parts of this software, except Netflow sources are distributed under GPLv3 terms.
Netflow sources are distributed under MIT terms.

Credits
-------

* Alexander Uvarov [http://github.com/wildchild](http://github.com/wildchild)
* Artem Teslenko [http://github.com/ates](http://github.com/ates)
