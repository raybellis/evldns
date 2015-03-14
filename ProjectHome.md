This library combines [libevent's](http://monkey.org/~provos/libevent/) high speed event handling code with [ldns's](http://www.nlnetlabs.nl/projects/ldns/) DNS packet manipulation.

It's designed to allow easy implementation of fast, light-weight custom DNS servers.

Example applications include an AS112 DNS server in under 200 lines of code capable of 60 kqps on an HP DL385 server.

#### Limitations ####

Call-back functions must return quickly.  evldns is single threaded and is not currently suitable for applications where (for example) upstream DNS queries or external database queries are necessary.

### Pre-requisites ###
  * ldns 1.5.0 or later
  * libevent 1.4.9 or later (may work with earlier versions, but untested)

The code has been built and tested on CentOS 5.2 through 6.5 and MacOS X 10.5.7+.  It's known to have issues compiling on Slackware and potentially other systems with glibc versions prior to 2.5.