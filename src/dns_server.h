#ifndef _DNS_SERVER_H_
#define _DNS_SERVER_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <uv.h>

struct dns_server_s;

typedef void (*dns_req_received_cb)(struct dns_server_s *dns_server, void *data,
                                    struct sockaddr_in addr, uint16_t tx_id,
                                    uint16_t flags, const char *name, int type);

typedef struct dns_server_s {
  uv_loop_t *loop;
  dns_req_received_cb cb;
  void *cb_data;

  uv_udp_t handle;
} dns_server_t;

void dns_server_init(dns_server_t *d, uv_loop_t *loop,
                     const char *listen_addr, int listen_port,
                     dns_req_received_cb cb, void *data);

// Sends a DNS response 'buf' of length 'blen' to 'raddr'.
void dns_server_respond(dns_server_t *d, struct sockaddr_in raddr, char *buf,
                        int blen);

void dns_server_cleanup(dns_server_t *d);

#endif // _DNS_SERVER_H_
