#include <sys/socket.h>
#include <sys/types.h>

#include <ares.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dns_poller.h"
#include "logging.h"

/* TBD: At the moment this code only shares one socket which seems somehow 
 * to work but a cleaner and more scalable solution would be to create
 * individual sockets and handles. */

static void sock_cb(uv_poll_t *w, int status, int revents) {
  dns_poller_t *d = (dns_poller_t *)w->data;
  if (status < 0) {
    DLOG("Socket poll status error %s\n", uv_err_name(status));
    ares_process_fd(d->ares, d->sock, d->sock);
    return;
  }
  ares_process_fd(d->ares, (revents & UV_READABLE) ? d->sock : ARES_SOCKET_BAD,
                  (revents & UV_WRITABLE) ? d->sock : ARES_SOCKET_BAD);
}

static void sock_state_cb(void *data, ares_socket_t sock, int read, int write) {
  dns_poller_t *d = (dns_poller_t *)data;
  if (!read && !write) {
    uv_close((uv_handle_t *)&d->poll_handle, NULL);
    d->poll_handle.data = NULL;
  } else {
    if (d->poll_handle.data == NULL) {
      uv_poll_init_socket(d->loop, &d->poll_handle, sock);
      d->poll_handle.data = d;
      d->sock = sock;
    }
    uv_poll_start(&d->poll_handle,
                  (read ? UV_READABLE : 0) | (write ? UV_WRITABLE : 0),
                  sock_cb);
  }
}

static void ares_cb(void *arg, int status, int timeouts, struct hostent *h) {
  dns_poller_t *d = (dns_poller_t *)arg;
  if (status != ARES_SUCCESS) {
    WLOG("DNS lookup failed: %d", status);
  } else if (!h || h->h_length < 1) {
    WLOG("No hosts.");
  } else {
    d->cb(d->cb_data, (struct sockaddr_in *)h->h_addr_list[0]);
  }
}

static void timer_cb(uv_timer_t *w) {
  dns_poller_t *d = (dns_poller_t *)w->data;
  ares_gethostbyname(d->ares, d->hostname, AF_INET, ares_cb, d);
}

void dns_poller_init(dns_poller_t *d, uv_loop_t *loop,
                     const char *bootstrap_dns, const char *hostname,
                     int interval_seconds, dns_poller_cb cb, void *cb_data) {
  int r;
  ares_library_init(ARES_LIB_INIT_ALL);

  struct ares_options options;
  options.sock_state_cb = sock_state_cb;
  options.sock_state_cb_data = d;

  options.servers = NULL;
  options.nservers = 0;
  char *csv = strdup(bootstrap_dns);
  if (!csv) {
    FLOG("Out of mem");
  }
  char *last = NULL;
  char *ipstr = strtok_r(csv, ",", &last);
  while (ipstr) {
    options.servers = (struct in_addr *)realloc(
        options.servers, sizeof(struct in_addr)*(options.nservers + 1));
    if (!options.servers) {
      FLOG("Out of mem");
    }
    if (ares_inet_pton(AF_INET, ipstr, 
                       &options.servers[options.nservers++]) != 1) {
      FLOG("Failed to parse '%s'", ipstr);
    }
    ipstr = strtok_r(NULL, ",", &last);
  }
  free(csv);

  if ((r = ares_init_options(
      &d->ares, &options, 
      ARES_OPT_SOCK_STATE_CB | ARES_OPT_SERVERS)) != ARES_SUCCESS) {
    FLOG("ares_init_options error: %s", ares_strerror(r));
  }

  free(options.servers);

  d->loop = loop;
  d->hostname = hostname;
  d->cb = cb;
  d->cb_data = cb_data;
  d->poll_handle.data = NULL;

  uv_timer_init(d->loop, &d->timer);
  d->timer.data = d;
  uv_timer_start(&d->timer, timer_cb, 0, interval_seconds);
}

void dns_poller_cleanup(dns_poller_t *d) {
  uv_timer_stop(&d->timer);
  ares_destroy(d->ares);
  ares_library_cleanup();
}
