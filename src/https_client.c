#ifndef _WIN32
	#include <sys/socket.h>
#else
	# define WIN32_LEAN_AND_MEAN
	# include <winsock2.h>
	# include <windows.h>
# endif

#include <sys/types.h>
#ifndef _WIN32
	#include <arpa/inet.h>
#endif
#include <curl/curl.h>
#include <errno.h>
#ifndef _WIN32
	#include <grp.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <pwd.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "https_client.h"
#include "json_to_dns.h"
#include "logging.h"
#include "options.h"

static size_t write_buffer(void *buf, size_t size, size_t nmemb, void *userp) {
  struct https_fetch_ctx *ctx = (struct https_fetch_ctx *)userp;
  unsigned char *new_buf = (unsigned char *)realloc(
      ctx->buf, ctx->buflen + size * nmemb + 1);
  if (new_buf == NULL) {
    ELOG("Out of memory!");
    return 0;
  }
  ctx->buf = new_buf;
  memcpy(&(ctx->buf[ctx->buflen]), buf, size * nmemb);
  ctx->buflen += size * nmemb;
  // We always expect to receive valid non-null ASCII but just to be safe...
  ctx->buf[ctx->buflen] = '\0';
  return size * nmemb;
}

static curl_context_t *create_curl_context(https_client_t *c,
                                           curl_socket_t sockfd) {
  curl_context_t *context;

  context = (curl_context_t *)malloc(sizeof *context);
  context->sockfd = sockfd;
  context->c = c;
  uv_poll_init_socket(c->loop, &context->poll_handle, sockfd);
  context->poll_handle.data = context;

  return context;
}

static void https_fetch_ctx_init(https_client_t *client,
                                 struct https_fetch_ctx *ctx, const char *url,
                                 struct curl_slist *resolv,
                                 https_response_cb cb, void *cb_data) {
  ctx->curl = curl_easy_init();
  ctx->cb = cb;
  ctx->cb_data = cb_data;
  ctx->buf = NULL;
  ctx->buflen = 0;
  ctx->next = client->fetches;
  client->fetches = ctx;

  CURLcode res;
  if ((res = curl_easy_setopt(ctx->curl, CURLOPT_RESOLVE, resolv)) !=
      CURLE_OK) {
    FLOG("CURLOPT_RESOLV error: %s", curl_easy_strerror(res));
  }

  DLOG("Requesting HTTP/1.1: %d\n", client->opt->use_http_1_1);
  curl_easy_setopt(ctx->curl, CURLOPT_HTTP_VERSION,
                   client->opt->use_http_1_1 ?
                   CURL_HTTP_VERSION_1_1 :
                   CURL_HTTP_VERSION_2_0);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, &write_buffer);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, ctx);
  curl_easy_setopt(ctx->curl, CURLOPT_TCP_KEEPALIVE, 5L);
  curl_easy_setopt(ctx->curl, CURLOPT_USERAGENT, "dns-to-https-proxy/0.2");
  curl_easy_setopt(ctx->curl, CURLOPT_NOSIGNAL, 0);
  curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, 2 /* seconds */);
  // We know Google supports this, so force it.
  curl_easy_setopt(ctx->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
  if (client->opt->curl_proxy) {
    DLOG("Using curl proxy: %s", client->opt->curl_proxy);
    if ((res = curl_easy_setopt(ctx->curl, CURLOPT_PROXY,
                                client->opt->curl_proxy)) != CURLE_OK) {
      FLOG("CURLOPT_PROXY error: %s", curl_easy_strerror(res));
    }
  }
  curl_multi_add_handle(client->curlm, ctx->curl);
}

static void https_fetch_ctx_cleanup(https_client_t *client,
                                    struct https_fetch_ctx *ctx) {
  struct https_fetch_ctx *last = NULL;
  struct https_fetch_ctx *cur = client->fetches;
  while (cur) {
    if (cur == ctx) {
      curl_multi_remove_handle(client->curlm, ctx->curl);
      if (client->opt->loglevel <= LOG_DEBUG) {
        CURLcode res;
        long long_resp = 0;
        char *str_resp = NULL;
        if ((res = curl_easy_getinfo(
                ctx->curl, CURLINFO_EFFECTIVE_URL, &str_resp)) != CURLE_OK) {
          ELOG("CURLINFO_EFFECTIVE_URL: %s", curl_easy_strerror(res));
        } else {
          DLOG("CURLINFO_EFFECTIVE_URL: %s", str_resp);
        }
        if ((res = curl_easy_getinfo(
                ctx->curl, CURLINFO_REDIRECT_URL, &str_resp)) != CURLE_OK) {
          ELOG("CURLINFO_REDIRECT_URL: %s", curl_easy_strerror(res));
        } else if (str_resp != NULL) {
          DLOG("CURLINFO_REDIRECT_URL: %s", str_resp);
        }
        if ((res = curl_easy_getinfo(
                ctx->curl, CURLINFO_RESPONSE_CODE, &long_resp)) != CURLE_OK) {
          ELOG("CURLINFO_RESPONSE_CODE: %s", curl_easy_strerror(res));
        } else if (long_resp != 200) {
          DLOG("CURLINFO_RESPONSE_CODE: %d", long_resp);
        }
        if ((res = curl_easy_getinfo(
                ctx->curl, CURLINFO_SSL_VERIFYRESULT, &long_resp)) != CURLE_OK) {
          ELOG("CURLINFO_SSL_VERIFYRESULT: %s", curl_easy_strerror(res));
        } else if (long_resp != CURLE_OK) {
          ELOG("CURLINFO_SSL_VERIFYRESULT: %s", curl_easy_strerror(long_resp));
        }
        if ((res = curl_easy_getinfo(
                ctx->curl, CURLINFO_OS_ERRNO, &long_resp)) != CURLE_OK) {
          ELOG("CURLINFO_OS_ERRNO: %s", curl_easy_strerror(res));
        } else if (long_resp != 0) {
          ELOG("CURLINFO_OS_ERRNO: %d", long_resp);
        }
#ifdef CURLINFO_HTTP_VERSION
        if ((res = curl_easy_getinfo(
                ctx->curl, CURLINFO_HTTP_VERSION, &long_resp)) != CURLE_OK) {
          ELOG("CURLINFO_HTTP_VERSION: %s", curl_easy_strerror(res));
        } else {
          switch (long_resp) {
            case CURL_HTTP_VERSION_1_0:
              DLOG("CURLINFO_HTTP_VERSION: %s", "1.0");
              break;
            case CURL_HTTP_VERSION_1_1:
              DLOG("CURLINFO_HTTP_VERSION: %s", "1.1");
              break;
            case CURL_HTTP_VERSION_2_0:
              DLOG("CURLINFO_HTTP_VERSION: %s", "2");
              break;
            default:
              DLOG("CURLINFO_HTTP_VERSION: %d", long_resp);
          }
        }
#endif
#ifdef CURLINFO_PROTOCOL
        if ((res = curl_easy_getinfo(
                ctx->curl, CURLINFO_PROTOCOL, &long_resp)) != CURLE_OK) {
          ELOG("CURLINFO_PROTOCOL: %s", curl_easy_strerror(res));
        } else if (long_resp != CURLPROTO_HTTPS) {
          DLOG("CURLINFO_PROTOCOL: %d", long_resp);
        }
#endif

        double namelookup_time, connect_time, appconnect_time, pretransfer_time;
        double starttransfer_time, total_time;
        if (curl_easy_getinfo(ctx->curl,
                              CURLINFO_NAMELOOKUP_TIME, &namelookup_time) != CURLE_OK ||
            curl_easy_getinfo(ctx->curl,
                              CURLINFO_CONNECT_TIME, &connect_time) != CURLE_OK ||
            curl_easy_getinfo(ctx->curl,
                              CURLINFO_APPCONNECT_TIME, &appconnect_time) != CURLE_OK ||
            curl_easy_getinfo(ctx->curl,
                              CURLINFO_PRETRANSFER_TIME, &pretransfer_time) != CURLE_OK ||
            curl_easy_getinfo(ctx->curl,
                              CURLINFO_STARTTRANSFER_TIME, &starttransfer_time) != CURLE_OK ||
            curl_easy_getinfo(ctx->curl,
                              CURLINFO_TOTAL_TIME, &total_time) != CURLE_OK) {
          ELOG("Err getting timing");
        } else {
          DLOG("Times: %lf, %lf, %lf, %lf, %lf, %lf",
               namelookup_time, connect_time, appconnect_time, pretransfer_time,
               starttransfer_time, total_time);
        }

      }
      curl_easy_cleanup(ctx->curl);
      ctx->cb(ctx->cb_data, ctx->buf, ctx->buflen);
      free(ctx->buf);

      if (last) {
        last->next = cur->next;
      } else {
        client->fetches = cur->next;
      }
      return;
    }
    last = cur;
    cur = cur->next;
  }
}

static void check_multi_info(https_client_t *c) {
  CURLMsg *msg;
  int msgs_left;
  while ((msg = curl_multi_info_read(c->curlm, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      struct https_fetch_ctx *n = c->fetches;
      while (n) {
        if (n->curl == msg->easy_handle) {
          https_fetch_ctx_cleanup(c, n);
          free(n);
          break;
        }
        n = n->next;
      }
    }
  }
}

static void curl_close_cb(uv_handle_t *handle) {
  curl_context_t *context = (curl_context_t *)handle->data;
  free(context);
}

static void sock_cb(uv_poll_t *w, int status, int revents) {
  curl_context_t *context = (curl_context_t *)w->data;
  https_client_t *c = context->c;
  if (c == NULL) {
    FLOG("c is NULL");
  }
  CURLMcode rc = curl_multi_socket_action(
      c->curlm, context->sockfd,
      (revents & UV_READABLE ? CURL_CSELECT_IN : 0) |
      (revents & UV_WRITABLE ? CURL_CSELECT_OUT : 0),
      &c->still_running);
  if (rc != CURLM_OK) {
    FLOG("curl_multi_socket_action: %d", rc);
  }
  check_multi_info(c);
}

static void timer_cb(uv_timer_t *w) {
  https_client_t *c = (https_client_t *)w->data;
  CURLMcode rc = curl_multi_socket_action(c->curlm, CURL_SOCKET_TIMEOUT, 0,
                                          &c->still_running);
  if (rc != CURLM_OK) {
    FLOG("curl_multi_socket_action: %d", rc);
  }
  check_multi_info(c);
}

static int multi_sock_cb(CURL *curl, curl_socket_t sock, int action,
                         https_client_t *c, void *sockp) {
#ifndef NO_LIBCURL_BUG_WORKAROUND
  static int curl_bug = -1;
  if (curl_bug == -1) {
    if (action == CURL_POLL_IN) {
      curl_bug = 0;
    } else if (action == CURL_POLL_REMOVE) {
      ELOG("libcurl bug detected: socket closed without ever being read.");
      ELOG("Activating workaround.  PERFORMANCE WILL BE GREATLY DEGRADED!");
      curl_bug = 1;
    }
  }
  if (curl_bug == 1 && action == CURL_POLL_REMOVE && c != NULL) {
    do {
      curl_multi_perform(c->curlm, &c->still_running);
    } while (c->still_running != 0);
  }
#endif
  curl_context_t *curl_context;
  int events = 0;

  switch (action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT:
      curl_context =
          sockp ? (curl_context_t *)sockp : create_curl_context(c, sock);

      curl_multi_assign(c->curlm, sock, (void *)curl_context);

      if (action != CURL_POLL_IN) {
        events |= UV_WRITABLE;
      }
      if (action != CURL_POLL_OUT) {
        events |= UV_READABLE;
      }

      uv_poll_start(&curl_context->poll_handle, events, sock_cb);
      break;
    case CURL_POLL_REMOVE:
      if (sockp) {
        uv_poll_stop(&((curl_context_t *)sockp)->poll_handle);
        /* not sure if that is needed */
        uv_close((uv_handle_t *)sockp, curl_close_cb);
        curl_multi_assign(c->curlm, sock, NULL);
      }
      break;
    default:
      abort();
  }

  return 0;
}

static int multi_timer_cb(CURLM *multi, long timeout_ms, https_client_t *c) {
  uv_timer_stop(&c->timer);
  if (timeout_ms > 0) {
    uv_timer_start(&c->timer, timer_cb, timeout_ms, 0);
  } else {
    timer_cb(&c->timer);
  }
  return 0;
}

void https_client_init(https_client_t *c, options_t *opt, uv_loop_t *loop) {
  int i = 0;

  memset(c, 0, sizeof(*c));
  c->loop = loop;
  c->curlm = curl_multi_init();
  c->fetches = NULL;
  c->timer.data = c;

  c->opt = opt;

  uv_timer_init(c->loop, &c->timer);

#if defined(CURLMOPT_PIPELINING) && defined(CURLPIPE_HTTP1) && \
  defined(CURLPIPE_MULTIPLEX)
  if (c->opt->use_http_1_1) {
    curl_multi_setopt(c->curlm, CURLMOPT_PIPELINING, CURLPIPE_HTTP1);
  } else {
    curl_multi_setopt(c->curlm, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  }
#endif
  curl_multi_setopt(c->curlm, CURLMOPT_MAX_TOTAL_CONNECTIONS, 8);
  curl_multi_setopt(c->curlm, CURLMOPT_MAXCONNECTS, 8);
  curl_multi_setopt(c->curlm, CURLMOPT_SOCKETDATA, c);
  curl_multi_setopt(c->curlm, CURLMOPT_SOCKETFUNCTION, multi_sock_cb);
  curl_multi_setopt(c->curlm, CURLMOPT_TIMERDATA, c);
  curl_multi_setopt(c->curlm, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
}

void https_client_fetch(https_client_t *c, const char *url,
                        struct curl_slist *resolv, https_response_cb cb,
                        void *data) {
  struct https_fetch_ctx *new_ctx =
      (struct https_fetch_ctx *)calloc(1, sizeof(struct https_fetch_ctx));
  if (!new_ctx) {
    FLOG("Out of mem");
  }
  https_fetch_ctx_init(c, new_ctx, url, resolv, cb, data);
}

void https_client_cleanup(https_client_t *c) {
  int i;

  while (c->fetches) {
    struct https_fetch_ctx *n = c->fetches;
    https_fetch_ctx_cleanup(c, n);
    free(n);
  }

  uv_timer_stop(&c->timer);
  curl_multi_cleanup(c->curlm);
}
