#include "wr/net.h"
#include "wr/dtls.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>

/* Datagram size used for the DTLS receive path. DTLS records carried by this
 * stack are at most WR_DTLS_RECV_MAX bytes; a larger datagram is dropped with
 * WR_ERR_OVERFLOW rather than silently truncated (a truncated record fails to
 * parse and the loss would be invisible). */
#define WR_IO_DATAGRAM_MAX 2048u

struct wr_io {
    int fd;
    bool owned;
    bool dtls;
    struct wr_dtls *dtls_obj;
    wr_io *under;
    uint8_t *queue;
    size_t queue_len;
    size_t queue_off;
    size_t queue_cap;
    uint32_t drops; /* datagrams discarded for being too large */
};

static int make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

wr_io *wr_io_udp_wrap(int fd)
{
    if (fd < 0) {
        return NULL;
    }
    wr_io *io = (wr_io *)calloc(1, sizeof(*io));
    if (!io) {
        return NULL;
    }
    io->fd = fd;
    io->owned = false;
    (void)make_nonblocking(fd);
    return io;
}

wr_io *wr_io_udp_create(const wr_endpoint *bind_ep, bool nonblocking)
{
    wr_endpoint local;
    if (bind_ep) {
        local = *bind_ep;
    } else {
        local.af = WR_AF_INET;
        local.port = 0;
        memset(local.ip.b.v4, 0, 4);
    }

    int fd = socket(local.af == WR_AF_INET ? AF_INET : AF_INET6,
                    SOCK_DGRAM, 0);
    if (fd < 0) {
        return NULL;
    }
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (local.af == WR_AF_INET6) {
        int off = 0;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }

    struct sockaddr_storage ss;
    socklen_t sl = (socklen_t)wr_endpoint_to_sockaddr(&local, &ss);
    if (sl == 0u || bind(fd, (struct sockaddr *)&ss, sl) != 0) {
        close(fd);
        return NULL;
    }

    (void)make_nonblocking(fd);
    WR_UNUSED(nonblocking);

    wr_io *io = (wr_io *)calloc(1, sizeof(*io));
    if (!io) {
        close(fd);
        return NULL;
    }
    io->fd = fd;
    io->owned = true;
    return io;
}

wr_io *wr_io_dtls_create(wr_io *underlying, struct wr_dtls *dtls)
{
    if (!underlying || !dtls) {
        return NULL;
    }
    wr_io *io = (wr_io *)calloc(1, sizeof(*io));
    if (!io) {
        return NULL;
    }
    io->fd = underlying->fd;
    io->owned = false;
    io->dtls = true;
    io->dtls_obj = dtls;
    io->under = underlying;
    io->queue_cap = 2048u;
    io->queue = (uint8_t *)malloc(io->queue_cap);
    if (!io->queue) {
        free(io);
        return NULL;
    }
    return io;
}

int wr_io_fd(const wr_io *io)
{
    return io ? io->fd : -1;
}

bool wr_io_local_addr(const wr_io *io, wr_endpoint *out)
{
    if (!io || !out) {
        return false;
    }
    if (io->dtls && io->under) {
        return wr_io_local_addr(io->under, out);
    }
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(io->fd, (struct sockaddr *)&ss, &sl) != 0) {
        return false;
    }
    return wr_endpoint_from_sockaddr((struct sockaddr *)&ss, out);
}

wr_status wr_io_send(wr_io *io, const wr_endpoint *dst, wr_span_c data,
                     size_t *sent)
{
    if (!io || (!io->dtls && !dst) || (!data.ptr && data.len != 0u)) {
        return WR_ERR_INVAL;
    }
    if (io->dtls) {
        wr_status st = wr_dtls_send(io->dtls_obj, data);
        if (sent) {
            *sent = st == WR_OK ? data.len : 0u;
        }
        return st;
    }
    struct sockaddr_storage ss;
    socklen_t sl = (socklen_t)wr_endpoint_to_sockaddr(dst, &ss);
    if (sl == 0u) {
        return WR_ERR_INVAL;
    }
    ssize_t n = sendto(io->fd, data.ptr, data.len, 0,
                       (struct sockaddr *)&ss, sl);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return WR_ERR_AGAIN;
        }
        return WR_ERR_IO;
    }
    if (sent) {
        *sent = (size_t)n;
    }
    return WR_OK;
}

/* Receive one datagram. A datagram larger than `buf` is discarded as a whole
 * and reported as WR_ERR_OVERFLOW: MSG_TRUNC tells us the datagram did not
 * fit, and the kernel has already dropped the remainder, so the socket is left
 * clean instead of delivering a truncated record to the parser. */
static wr_status recv_datagram(int fd, wr_span buf, wr_endpoint *src,
                               size_t *out_len)
{
    struct sockaddr_storage ss;
    struct iovec iov;
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    iov.iov_base = buf.ptr;
    iov.iov_len = buf.len;
    mh.msg_name = &ss;
    mh.msg_namelen = sizeof(ss);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    ssize_t n = recvmsg(fd, &mh, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return WR_ERR_AGAIN;
        }
        return WR_ERR_IO;
    }
    if ((mh.msg_flags & MSG_TRUNC) != 0) {
        return WR_ERR_OVERFLOW;
    }
    if (src && mh.msg_namelen != 0u) {
        (void)wr_endpoint_from_sockaddr((struct sockaddr *)&ss, src);
    }
    if (out_len) {
        *out_len = (size_t)n;
    }
    return WR_OK;
}

wr_status wr_io_recv(wr_io *io, wr_endpoint *src, wr_span buf, wr_span *out)
{
    if (!io || (!buf.ptr && buf.len != 0u)) {
        return WR_ERR_INVAL;
    }
    if (io->dtls) {
        if (io->queue_off >= io->queue_len) {
            return WR_ERR_AGAIN;
        }
        size_t avail = io->queue_len - io->queue_off;
        /* A DTLS record is a datagram: truncating it would hand the caller a
         * silently corrupted SCTP packet. Refuse instead. */
        if (avail > buf.len) {
            return WR_ERR_OVERFLOW;
        }
        size_t n = avail;
        memcpy(buf.ptr, io->queue + io->queue_off, n);
        io->queue_off += n;
        if (io->queue_off == io->queue_len) {
            io->queue_off = 0u;
            io->queue_len = 0u;
        }
        if (out) {
            out->ptr = buf.ptr;
            out->len = n;
        }
        (void)src; /* DTLS is point-to-point; the source is implicit. */
        return WR_OK;
    }
    size_t n = 0u;
    wr_status st = recv_datagram(io->fd, buf, src, &n);
    if (st != WR_OK) {
        return st;
    }
    if (out) {
        out->ptr = buf.ptr;
        out->len = n;
    }
    return WR_OK;
}

wr_status wr_io_wait(wr_io *io, uint32_t timeout_ms, bool *ready)
{
    if (!io || !ready) {
        return WR_ERR_INVAL;
    }
    if (io->dtls) {
        *ready = io->queue_len != 0u;
        if (*ready) {
            return WR_OK;
        }
        /* Records decrypted by an earlier input are ready without new traffic
         * on the underlying socket. */
        wr_span_c app;
        if (wr_dtls_recv(io->dtls_obj, &app)) {
            size_t n = app.len < io->queue_cap ? app.len : io->queue_cap;
            memcpy(io->queue, app.ptr, n);
            io->queue_len = n;
            io->queue_off = 0u;
            *ready = true;
            return WR_OK;
        }
        uint8_t buf[WR_IO_DATAGRAM_MAX];
        for (int i = 0; i < 8; ++i) {
            bool under_ready = false;
            if (wr_io_wait(io->under, i == 0 ? timeout_ms : 0u,
                           &under_ready) != WR_OK || !under_ready) {
                break;
            }
            wr_endpoint from;
            wr_span data;
            wr_status rst =
                wr_io_recv(io->under, &from, wr_span_make(buf, sizeof(buf)),
                           &data);
            if (rst == WR_ERR_AGAIN) {
                break;
            }
            if (rst == WR_ERR_OVERFLOW) {
                /* Datagram larger than any record this stack accepts: the
                 * kernel discarded it. Count it so the loss is observable
                 * instead of looking like a silent timeout. */
                io->drops++;
                continue;
            }
            if (rst != WR_OK) {
                break;
            }
            (void)wr_dtls_input(io->dtls_obj, &from, wr_span_upcast(data));
            if (wr_dtls_recv(io->dtls_obj, &app)) {
                size_t n = app.len < io->queue_cap ? app.len : io->queue_cap;
                memcpy(io->queue, app.ptr, n);
                io->queue_len = n;
                io->queue_off = 0u;
                *ready = true;
                return WR_OK;
            }
        }
        *ready = false;
        return WR_OK;
    }
    struct pollfd pfd;
    pfd.fd = io->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int rc;
    do {
        rc = poll(&pfd, 1, (int)timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return WR_ERR_IO;
    }
    *ready = rc > 0 && (pfd.revents & POLLIN) != 0;
    return WR_OK;
}

uint32_t wr_io_drops(const wr_io *io)
{
    return io ? io->drops : 0u;
}

void wr_io_destroy(wr_io *io)
{
    if (!io) {
        return;
    }
    if (io->owned && io->fd >= 0) {
        close(io->fd);
    }
    free(io->queue);
    free(io);
}