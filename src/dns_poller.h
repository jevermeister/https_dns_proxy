#ifndef _DNS_POLLER_H_
#define _DNS_POLLER_H_

#include <ares.h>
#include <uv.h>

// Callback to be called periodically when we get a valid DNS response.
typedef void (*dns_poller_cb)(void *data, struct sockaddr_in *addr);

typedef struct {
  ares_channel ares;
  uv_loop_t *loop;
  const char *hostname;
  dns_poller_cb cb;
  void *cb_data;

  uv_timer_t timer;
  
  uv_poll_t poll_handle;
  ares_socket_t sock;
} dns_poller_t;

// Initializes c-ares and starts a timer for periodic DNS resolution on the
// provided uv_loop. `bootstrap_dns` is a comma-separated list of DNS servers to
// use for the lookup `hostname` every `interval_seconds`. For each successful
// lookup, `cb` will be called with the resolved address.
//
// Note: hostname *not* copied. It should remain valid until
// dns_poller_cleanup called.
void dns_poller_init(dns_poller_t *d, uv_loop_t *loop,
                     const char *bootstrap_dns, const char *hostname,
                     int interval_seconds, dns_poller_cb cb, void *cb_data);

// Tears down timer and frees resources associated with a dns poller.
void dns_poller_cleanup(dns_poller_t *d);

#endif
