#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "jail_packet.h"
#include "pevent.h"
#include "log.h"
#include "utils.h"

#ifdef gcc_struct
#define JP_ATTRS __attribute__((packed, aligned(1), gcc_struct))
#else
#define JP_ATTRS __attribute__((packed,  aligned(1)))
#endif

typedef struct jail_packet {
    uint8_t type;
    uint16_t size;
} JP_ATTRS jail_packet;

#define PKT_SIZ(pkt) (sizeof(jail_packet) + sizeof(*pkt))
#define PKT_SUB(pkt_ptr) ((unsigned char *)pkt_ptr + sizeof(jail_packet))

#define JP_MAGIC1 0xDEADC0DE
#define JP_MAGIC2 0xDEADBEEF

typedef struct jail_packet_hello {
    uint32_t magic1;
    uint32_t magic2;
} JP_ATTRS jail_packet_hello;

typedef int (*packet_callback)(jail_packet_ctx *ctx, jail_packet *pkt,
                               event_buf *write_buf);

typedef struct jail_packet_callback {
    uint8_t type;
    packet_callback pc;
} jail_packet_callback;

static ssize_t pkt_header_read(unsigned char *buf, size_t siz);
static int pkt_hello(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf);
static int pkt_user(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf);
static int pkt_pass(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf);
static int pkt_start(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf);
static int pkt_data(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf);
static int pkt_respok(jail_packet_ctx *ctx, jail_packet *pkt,
                      event_buf *write_buf);
static int pkt_resperr(jail_packet_ctx *ctx, jail_packet *pkt,
                       event_buf *write_buf);
static int jail_packet_io(event_ctx *ctx, int src_fd, void *user_data);
static int jail_packet_pkt(event_ctx *ev_ctx, event_buf *read_buf,
                           event_buf *write_buf, void *user_data);

#define PKT_CB(type, cb) \
    { type, cb }
static const jail_packet_callback jpc[] = {
    PKT_CB(PKT_INVALID, NULL),
    PKT_CB(PKT_HELLO,   pkt_hello),
    PKT_CB(PKT_USER,    pkt_user),
    PKT_CB(PKT_PASS,    pkt_pass),
    PKT_CB(PKT_START,   pkt_start),
    PKT_CB(PKT_DATA,    pkt_data),
    PKT_CB(PKT_RESPOK,  pkt_respok),
    PKT_CB(PKT_RESPERR, pkt_resperr)
};


static ssize_t pkt_header_read(unsigned char *buf, size_t siz)
{
    jail_packet *pkt;

    if (siz < sizeof(*pkt))
        return -1;
    pkt = (jail_packet *) buf;

    if (pkt->type >= SIZEOF(jpc))
        return -1;

    pkt->size = ntohs(pkt->size);
    if (siz < pkt->size)
        return 0;

    return pkt->size + sizeof(*pkt);
}

static int pkt_write(event_buf *write_buf, uint8_t type, unsigned char *buf,
                     size_t siz)
{
    jail_packet pkt;

    pkt.type = type;
    pkt.size = htons(siz);

    if (event_buf_fill(write_buf, (char *) &pkt, sizeof pkt) ||
        (buf && event_buf_fill(write_buf, (char *) buf, siz)))
    {
        return 1;
    }

    return 0;
}

static int pkt_hello(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf)
{
    jail_packet_hello *pkt_hello;

    if (ctx->ctype != JC_SERVER)
        return 1;

    printf("HELLO !!!\n");
    if (ctx->pstate != JP_HANDSHAKE)
        return 1;
    pkt_hello = (jail_packet_hello *) PKT_SUB(pkt);
    pkt_hello->magic1 = ntohl(pkt_hello->magic1);
    pkt_hello->magic2 = ntohl(pkt_hello->magic2);
    if (pkt_hello->magic1 != JP_MAGIC1 ||
        pkt_hello->magic2 != JP_MAGIC2)
    {
        return 1;
    }

    if (pkt_write(write_buf, PKT_RESPOK, NULL, 0))
        return 1;

    ctx->pstate = JP_START;

    return 0;
}

static int pkt_user(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
    (void) write_buf;

    if (ctx->ctype != JC_SERVER || ctx->pstate != JP_START)
        return 1;

    printf("USER !!!\n");
    return 0;
}

static int pkt_pass(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
    (void) write_buf;

    if (ctx->ctype != JC_SERVER || ctx->pstate != JP_START)
        return 1;

    printf("PASS !!!\n");
    return 0;
}

static int pkt_start(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf)
{
    if (ctx->ctype != JC_SERVER || ctx->pstate != JP_START)
        return 1;

    printf("START !!!\n");
    return 0;
}

static int pkt_data(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
    return 0;
}

static int pkt_respok(jail_packet_ctx *ctx, jail_packet *pkt,
                      event_buf *write_buf)
{
    return 0;
}

static int pkt_resperr(jail_packet_ctx *ctx, jail_packet *pkt,
                       event_buf *write_buf)
{
    return 1;
}

static int jail_packet_io(event_ctx *ev_ctx, int src_fd, void *user_data)
{
    int dest_fd;
    jail_packet_ctx *pkt_ctx = (jail_packet_ctx *) user_data;
    forward_state fwd_state;

    (void) ev_ctx;
    (void) src_fd;
    (void) pkt_ctx;

    if (src_fd == pkt_ctx->connection.client_fd) {
        dest_fd = pkt_ctx->connection.jail_fd;
    } else if (src_fd == pkt_ctx->connection.jail_fd) {
        dest_fd = pkt_ctx->connection.client_fd;
    } else return 0;

    fwd_state = event_forward_connection(ev_ctx, dest_fd, jail_packet_pkt,
                                         user_data);

    switch (fwd_state) {
        case CON_IN_TERMINATED:
        case CON_OUT_TERMINATED:
            ev_ctx->active = 0;
        case CON_OK:
            return 1;
        case CON_IN_ERROR:
        case CON_OUT_ERROR:
            ev_ctx->active = 0;
            return 0;
    }

    return 1;
}

static int jail_packet_pkt(event_ctx *ev_ctx, event_buf *read_buf,
                           event_buf *write_buf, void *user_data)
{
    jail_packet_ctx *pkt_ctx = (jail_packet_ctx *) user_data;
    jail_packet *pkt;
    ssize_t pkt_siz;
    off_t pkt_off = 0;

    while (1) {
        pkt_siz = pkt_header_read((unsigned char *) read_buf->buf + pkt_off,
                                  read_buf->buf_used);
        if (pkt_siz < 0) {
            /* invalid jail packet */
            ev_ctx->active = 0;
            return 0;
        } else if (pkt_siz == 0)
            /* require more data */
            return 0;

        pkt = (jail_packet *)(read_buf->buf + pkt_off);
        if (jpc[pkt->type].pc &&
            jpc[pkt->type].pc(pkt_ctx, pkt, write_buf))
        {
            pkt_ctx->pstate = JP_INVALID;
            break;
        }

        pkt_off += pkt_siz;
        read_buf->buf_used -= pkt_siz;
    }

    if (pkt_off)
        event_buf_discard(read_buf, pkt_off);

    if (event_buf_drain(write_buf) < 0)
        pkt_ctx->pstate = JP_INVALID;

    if (pkt_ctx->pstate == JP_NONE || pkt_ctx->pstate == JP_INVALID)
        ev_ctx->active = 0;

    return 1;
}

int jail_packet_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    assert(ctx && pkt_ctx);
    assert(pkt_ctx->pstate == JP_HANDSHAKE);

    pkt_ctx->pstate = JP_DATA;

    return event_loop(ctx, jail_packet_io, pkt_ctx);
}

event_ctx *jail_client_handshake(int server_fd, jail_packet_ctx *pkt_ctx)
{
    event_ctx *ev_ctx = NULL;
    event_buf write_buf = WRITE_BUF(server_fd);
    size_t user_len, pass_len;
    jail_packet_hello ph;

    assert(pkt_ctx);
    assert(pkt_ctx->pstate == JP_NONE);
    assert(pkt_ctx->ctype == JC_CLIENT);

    pkt_ctx->pstate = JP_HANDSHAKE;

    event_init(&ev_ctx);
    if (event_setup(ev_ctx)) {
        E_STRERR("Jail protocol event context creation for jail tty fd %d",
            server_fd);
        goto finish;
    }
    if (event_add_fd(ev_ctx, server_fd, NULL)) {
        E_STRERR("Jail protocol event context for fd %d", server_fd);
        goto finish;
    }

    ph.magic1 = htonl(JP_MAGIC1);
    ph.magic2 = htonl(JP_MAGIC2);
    if (pkt_write(&write_buf, PKT_HELLO,
                  (unsigned char *) &ph, sizeof(ph)))
    {
        goto finish;
    }

    if (pkt_ctx->user) {
        user_len = strnlen(pkt_ctx->user, USER_LEN);
        if (pkt_write(&write_buf, PKT_USER,
            (unsigned char *) pkt_ctx->user, user_len))
        {
            goto finish;
        }
    }
    if (pkt_ctx->pass) {
        pass_len = strnlen(pkt_ctx->pass, PASS_LEN);
        if (pkt_write(&write_buf, PKT_PASS,
            (unsigned char *) pkt_ctx->pass, pass_len))
        {
            goto finish;
        }
    }

    if (pkt_write(&write_buf, PKT_START, NULL, 0))
        goto finish;

    if (event_buf_drain(&write_buf) < 0)
        goto finish;
    pkt_ctx->is_valid = 1;

    if (event_loop(ev_ctx, jail_packet_io, pkt_ctx)) {
        E_STRERR("Jail protocol handshake for fd %d failed", server_fd);
        goto finish;
    }

    return ev_ctx;
finish:
    event_free(&ev_ctx);
    return NULL;
}

int jail_server_handshake(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    assert(ctx && pkt_ctx);
    assert(pkt_ctx->pstate == JP_NONE);
    assert(pkt_ctx->ctype == JC_SERVER);

    pkt_ctx->pstate = JP_HANDSHAKE;

    return event_loop(ctx, jail_packet_io, pkt_ctx);
}
