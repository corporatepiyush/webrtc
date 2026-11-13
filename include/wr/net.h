#ifndef WR_NET_H
#define WR_NET_H

#include "wr/base.h"

#include <sys/socket.h>

typedef enum { WR_AF_INET = 4, WR_AF_INET6 = 6 } wr_af;

typedef struct {
    union {
        uint8_t v4[4];
        uint8_t v6[16];
    } b;
    uint32_t scope_id;
} wr_ip;

typedef struct {
    wr_ip ip;
    uint16_t port;
    wr_af af;
} wr_endpoint;

void wr_endpoint_v4(wr_endpoint *e, const uint8_t b[4], uint16_t port);
void wr_endpoint_v6(wr_endpoint *e, const uint8_t b[16], uint32_t scope,
                    uint16_t port);
void wr_endpoint_loopback(wr_endpoint *e, uint16_t port);
bool wr_endpoint_parse(wr_span_c s, uint16_t default_port, wr_endpoint *out);
size_t wr_endpoint_format(const wr_endpoint *e, char *buf, size_t cap);
bool wr_endpoint_eq(const wr_endpoint *a, const wr_endpoint *b);
bool wr_endpoint_is_loopback(const wr_endpoint *e);
bool wr_endpoint_is_unspec(const wr_endpoint *e);

size_t wr_endpoint_to_sockaddr(const wr_endpoint *e, struct sockaddr_storage *ss);
bool wr_endpoint_from_sockaddr(const struct sockaddr *sa, wr_endpoint *out);

/* ------------------------------------------------------------------------- */
/* UDP I/O                                                                    */
/* ------------------------------------------------------------------------- */

typedef struct wr_io wr_io;
struct wr_dtls;

wr_io *wr_io_udp_create(const wr_endpoint *bind, bool nonblocking);
wr_io *wr_io_udp_wrap(int fd);
wr_io *wr_io_dtls_create(wr_io *underlying, struct wr_dtls *dtls);
int wr_io_fd(const wr_io *io);
bool wr_io_local_addr(const wr_io *io, wr_endpoint *out);
wr_status wr_io_send(wr_io *io, const wr_endpoint *dst, wr_span_c data,
                     size_t *sent);
wr_status wr_io_recv(wr_io *io, wr_endpoint *src, wr_span buf, wr_span *out);
wr_status wr_io_wait(wr_io *io, uint32_t timeout_ms, bool *ready);
void wr_io_destroy(wr_io *io);

/* ------------------------------------------------------------------------- */
/* Timers                                                                     */
/* ------------------------------------------------------------------------- */

typedef struct wr_timer wr_timer;
typedef void (*wr_timer_fn)(void *ctx, uint64_t now_ms);

wr_timer *wr_timer_create(size_t capacity);
void wr_timer_destroy(wr_timer *t);
wr_status wr_timer_schedule(wr_timer *t, uint64_t at_ms, wr_timer_fn fn,
                            void *ctx, uint64_t *id);
bool wr_timer_cancel(wr_timer *t, uint64_t id);
uint64_t wr_timer_next_deadline(const wr_timer *t, uint64_t now_ms);
uint32_t wr_timer_fire(wr_timer *t, uint64_t now_ms);

#endif /* WR_NET_H */