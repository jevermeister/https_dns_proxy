# https-dns-proxy

https\_dns\_proxy is a light-weight DNS&lt;--&gt;HTTPS, non-caching proxy for
Google's [DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/dns-over-https)
service.

Using DNS over HTTPS makes eavesdropping and spoofing of DNS traffic between you
and the HTTPS DNS provider (Google) much less likely. This of course only makes
sense if you trust Google as they're currently the only provider of such a
service.

Features:

* Tiny Size (<30kiB).
* Uses curl for HTTP/2 and pipelining, keeping resolve latencies extremely low.
* Single-threaded, non-blocking select() server for use on resource-starved 
  embedded systems.
* Designed to sit in front of dnsmasq or similar caching resolver for
  transparent use.

## BUILD

Depends on `c-ares`, `libcurl`, `libuv`.

On Debian-derived systems those are libc-ares-dev,
libcurl4-{openssl,nss,gnutls}-dev and libuv-dev respectively.
On Redhat-derived systems those are c-ares-devel, libcurl-devel and
libuv-devel.

```
$ cmake .
$ make
```

## INSTALL

There is no installer at this stage - just run it.

```
# ./https_dns_proxy -u nobody -g nogroup -d
```

## Usage

Just run it as a daemon and point traffic at it. Commandline flags are:

```
Usage: https_dns_proxy [-a <listen_addr>] [-p <listen_port>]
        [-e <subnet>] [-d] [-u <user>] [-g <group>] [-b <dns_servers>]
        [-l <logfile>]

  -a listen_addr    Local address to bind to. (127.0.0.1)
  -p listen_port    Local port to bind to. (5053)
  -e subnet_addr    An edns-client-subnet to use such as "203.31.0.0/16". ()
  -d                Daemonize.
  -u user           User to drop to launched as root. (nobody)
  -g group          Group to drop to launched as root. (nobody)
  -b dns_servers    Comma separated IPv4 address of DNS servers
                    to resolve dns.google.com. (8.8.8.8,8.8.4.4,145.100.185.15,
                    145.100.185.16,185.49.141.37,199.58.81.218,80.67.188.188)
  -t proxy_server   Optional HTTP proxy. e.g. socks5://127.0.0.1:1080
                    Remote name resolution will be used if the protocol
                    supports it (http, https, socks4a, socks5h), otherwise
                    initial DNS resolution will still be done via the
                    bootstrap DNS servers.
  -l logfile        Path to file to log to. (-)
  -x                Use HTTP/1.1 instead of HTTP/2. Useful with broken
                    or limited builds of libcurl (false).
  -v                Increase logging verbosity. (INFO)
```

## TODO

* Test coverage could be better.
* Load tests (that don't tax Google's infrastructure) would be nice.

## AUTHORS

* Aaron Drew (aarond10@gmail.com)
* Jan Schlemminger (libuv port)
