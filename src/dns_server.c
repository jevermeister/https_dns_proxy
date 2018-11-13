#include <sys/socket.h>
#include <sys/types.h>

#include <ares.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <ev.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dns_server.h"
#include "logging.h"

// Creates and bind a listening UDP socket for incoming requests.
static int get_listen_sock(const char *listen_addr, int listen_port) {
  struct sockaddr_in laddr;
  memset(&laddr, 0, sizeof(laddr));
  laddr.sin_family = AF_INET;
  laddr.sin_port = htons(listen_port);
  laddr.sin_addr.s_addr = inet_addr(listen_addr);
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    FLOG("Error creating socket");
  }
  if (bind(sock, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
    FLOG("Error binding %s:%d", listen_addr, listen_port);
  }

  ILOG("Listening on %s:%d", listen_addr, listen_port);
  return sock;
}

static void watcher_cb(struct ev_loop *loop, ev_io *w, int revents) {
  dns_server_t *d = (dns_server_t *)w->data;

  // A default MTU. We don't do TCP so any bigger is likely a waste.
  unsigned char buf[1500];
  struct sockaddr_in raddr;
  socklen_t raddr_size = sizeof(raddr);
  int len = recvfrom(w->fd, buf, sizeof(buf), 0, (struct sockaddr *)&raddr,
                     &raddr_size);
  if (len < 0) {
    WLOG("recvfrom failed: %s", strerror(errno));
    return;
  }
  
  d->cb(d, d->cb_data, raddr, buf, len);
}

void dns_server_init(dns_server_t *d, struct ev_loop *loop,
                     const char *listen_addr, int listen_port,
                     dns_req_received_cb cb, void *data) {
  d->loop = loop;
  d->sock = get_listen_sock(listen_addr, listen_port);
  d->cb = cb;
  d->cb_data = data;

  ev_io_init(&d->watcher, watcher_cb, d->sock, EV_READ);
  d->watcher.data = d;
  ev_io_start(d->loop, &d->watcher);
}

void dns_server_respond(dns_server_t *d, struct sockaddr_in raddr, char *buf,
                        int blen) {
  sendto(d->sock, buf, blen, 0, (struct sockaddr *)&raddr, sizeof(raddr));
}

void dns_server_cleanup(dns_server_t *d) {
  ev_io_stop(d->loop, &d->watcher);
  close(d->sock);
}
