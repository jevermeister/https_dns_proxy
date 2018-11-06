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
<<<<<<< HEAD
  ev_tstamp interval;
=======
  uint64_t interval;
>>>>>>> ade74d50bb43467b330f1b782730610ea64bcbc4

  if (status != ARES_SUCCESS) {
    interval = POLLER_INTVL_ERR;
    WLOG("DNS lookup failed: %s", ares_strerror(status));
  } else if (!h || h->h_length < 1) {
    interval = POLLER_INTVL_ERR;
    WLOG("No hosts.");
  } else {
    interval = POLLER_INTVL_NORM;
    d->cb(d->hostname, d->cb_data, (struct sockaddr_in *)h->h_addr_list[0]);
  }

<<<<<<< HEAD
  if(interval != d->timer.repeat) {
    DLOG("DNS poll interval changed from %.0lf -> %.0lf", d->timer.repeat, interval);
    ev_timer_stop(d->loop, &d->timer);
    ev_timer_set(&d->timer, interval, interval);
    ev_timer_start(d->loop, &d->timer);
=======
  if(interval != uv_timer_get_repeat(&d->timer)) {
    DLOG("DNS poll interval changed from %i -> %i", uv_timer_get_repeat(&d->timer) / 1000, interval / 1000);
    uv_timer_stop(&d->timer);
    uv_timer_set_repeat(&d->timer, interval);
>>>>>>> ade74d50bb43467b330f1b782730610ea64bcbc4
  }
}

static void timer_cb(uv_timer_t *w) {
  dns_poller_t *d = (dns_poller_t *)w->data;
  // Cancel any pending queries before making new ones. c-ares can't be depended on to
  // execute ares_cb() even after the specified query timeout has been reached, e.g. if
  // the packet was dropped without any response from the network. This also serves to
  // free memory tied up by any "zombie" queries.
  ares_cancel(d->ares);
  ares_gethostbyname(d->ares, d->hostname, AF_INET, ares_cb, d);
}

void dns_poller_init(dns_poller_t *d, uv_loop_t *loop,
                     const char *bootstrap_dns, const char *hostname,
                     dns_poller_cb cb, void *cb_data) {
<<<<<<< HEAD
  int i;
  for (i = 0; i < FD_SETSIZE; i++) {
    d->fd[i].fd = 0;
  }

=======
>>>>>>> ade74d50bb43467b330f1b782730610ea64bcbc4
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
    DLOG("Adding DNS server '%s' for bootstrap resolution.", ipstr);
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

<<<<<<< HEAD
  // Start with a shorter polling interval and switch after we've bootstrapped.
  ev_timer_init(&d->timer, timer_cb, 0, POLLER_INTVL_ERR);
=======
  uv_timer_init(d->loop, &d->timer);
>>>>>>> ade74d50bb43467b330f1b782730610ea64bcbc4
  d->timer.data = d;
  // Start with a shorter polling interval and switch after we've bootstrapped.
  uv_timer_start(&d->timer, timer_cb, 0, POLLER_INTVL_ERR);
}

void dns_poller_cleanup(dns_poller_t *d) {
  uv_timer_stop(&d->timer);
  ares_destroy(d->ares);
  ares_library_cleanup();
}
