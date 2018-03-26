#ifndef _HTTPS_CLIENT_H_
#define _HTTPS_CLIENT_H_

#include <arpa/inet.h>
#include <curl/curl.h>
#include <uv.h>
#include <stdint.h>

#include "options.h"

// Callback type for receiving data when a transfer finishes.
typedef void (*https_response_cb)(void *data, uint8_t *buf, uint32_t buflen);

// Internal: Holds state on an individual transfer.
struct https_fetch_ctx {
  CURL *curl;
  https_response_cb cb;
  void *cb_data;

  uint8_t *buf;
  uint32_t buflen;

  struct https_fetch_ctx *next;
};

// Holds state on the whole multiplexed CURL machine.
typedef struct {
  uv_loop_t *loop;
  CURLM *curlm;
  struct https_fetch_ctx *fetches;

  uv_timer_t timer;
  int still_running;

  options_t *opt;
} https_client_t;

typedef struct curl_context_s {
  uv_poll_t poll_handle;
  curl_socket_t sockfd;
  https_client_t *c;
} curl_context_t;

void https_client_init(https_client_t *c, options_t *opt, uv_loop_t *loop);

void https_client_fetch(https_client_t *c, const char *url,
                        struct curl_slist *resolv, https_response_cb cb,
                        void *data);

void https_client_cleanup(https_client_t *c);

#endif // _HTTPS_CLIENT_H_
