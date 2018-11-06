#ifndef _WIN32
	#include <sys/socket.h>
#else
	# define WIN32_LEAN_AND_MEAN
	# include <winsock2.h>
	# include <windows.h>
# endif

#include <sys/types.h>

#include <ares.h>
#ifndef _WIN32
	#include <arpa/inet.h>
#endif
#include <curl/curl.h>
#include <errno.h>
#include <uv.h>
#ifndef _WIN32
	#include <grp.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <pwd.h>
#endif
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dns_server.h"
#include "logging.h"

#define DNS_BUFFER_SIZE 1500

static void alloc_buffer(uv_handle_t *client, size_t suggested_size,
                         uv_buf_t *buf) {
  *buf = uv_buf_init(malloc(DNS_BUFFER_SIZE), DNS_BUFFER_SIZE);
}

void receive_request_cb(uv_udp_t *req, ssize_t nread, const uv_buf_t *recbuf,
                        const struct sockaddr *raddr, unsigned int ipflags) {
  if (nread <= 0) {
    /* 0 == nothing to read or empty UDP packet (depending on raddr == NULL)
     * < 0 is socket error, on both cases we have to free resources */
    if (nread < 0) {
      WLOG("Reading socket failed: %s", strerror(errno));
      uv_close((uv_handle_t *)req, NULL);
    }
    goto free_cb_resources;
  }
  dns_server_t *d = (dns_server_t *)req->data;
  unsigned char *p = recbuf->base;
  uint16_t tx_id = ntohs(*(uint16_t *)p);
  p += 2;
  uint16_t flags = ntohs(*(uint16_t *)p);
  p += 2;
  uint16_t num_q = ntohs(*(uint16_t *)p);
  p += 2;
  //uint16_t num_rr = ntohs(*(uint16_t *)p);
  p += 2;
  //uint16_t num_arr = ntohs(*(uint16_t *)p);
  p += 2;
  //uint16_t num_xrr = ntohs(*(uint16_t *)p);
  p += 2;
  if (num_q != 1) {
    DLOG("Malformed request received.");
    goto free_cb_resources;
  };
  char *domain_name;
  long enc_len;
  if (ares_expand_name(p, recbuf->base, nread, &domain_name, &enc_len) != ARES_SUCCESS) {
    DLOG("Malformed request received.");
    goto free_cb_resources;
  }
  p += enc_len;
  uint16_t type = ntohs(*(uint16_t *)p);
  p += 2;

  d->cb(d, d->cb_data, *((struct sockaddr_in*)raddr), tx_id, flags, domain_name, type);

  ares_free_string(domain_name);
free_cb_resources:
  free(recbuf->base);
}


void dns_server_init(dns_server_t *d, uv_loop_t *loop,
                     const char *listen_addr, int listen_port,
                     dns_req_received_cb cb, void *data) {
  d->loop = loop;
  d->cb = cb;
  d->cb_data = data;
  struct sockaddr_in laddr;
  
  uv_ip4_addr(listen_addr, listen_port, &laddr);
  int status = uv_udp_init(loop, &d->handle);
  if (status < 0) {
    FLOG("Error creating socket");
  }
  status = uv_udp_bind(&d->handle, (const struct sockaddr *)&laddr, 0);
  if (status < 0) {
    FLOG("Error binding %s:%d", listen_addr, listen_port);
  }

  ILOG("Listening on %s:%d", listen_addr, listen_port);

  d->handle.data = d;
  uv_udp_recv_start(&d->handle, alloc_buffer, receive_request_cb);
}

static void on_send(uv_udp_send_t *req, int status) {
  if (status < 0) {
    FLOG("DNS reply status error %s\n", uv_err_name(status));
  }
  free(req);
}

void dns_server_respond(dns_server_t *d, struct sockaddr_in raddr, char *buf,
                        int blen) {
  uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
  uv_buf_t reply = uv_buf_init(buf, blen);
  uv_udp_send(send_req, &d->handle, &reply, 1, (struct sockaddr *)&raddr,
              on_send);
}

void dns_server_cleanup(dns_server_t *d) {
  uv_close((uv_handle_t *)&d->handle, NULL);
}
