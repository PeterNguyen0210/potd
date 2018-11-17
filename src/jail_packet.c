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
#define PKT_SUB(pkt_ptr) (pkt_ptr + sizeof(jail_packet))

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
        return -1;

    return pkt->size + sizeof(*pkt);
}

static int pkt_write(event_buf *write_buf, uint8_t type, unsigned char *buf,
                     size_t siz)
{
    jail_packet pkt;

    if (siz < sizeof pkt)
        return 1;
    pkt.type = type;
    pkt.size = htons(siz);

    if (event_buf_fill(write_buf, (unsigned char *) &pkt, sizeof pkt) ||
        (buf && event_buf_fill(write_buf, buf, siz)))
    {
        return 1;
    }

    return 0;
}

static int pkt_hello(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf)
{
    jail_packet_hello *pkt_hello;

printf("PKT_HELLO !!!\n");
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

    if (ctx->ctype == JC_SERVER) {
        if (pkt_write(write_buf, PKT_RESPOK, NULL, 0))
            return 1;
    }

    return 0;
}

static int pkt_user(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
printf("PKT_USER !!!\n");
    return 0;
}

static int pkt_pass(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
printf("PKT_PASS !!!\n");
    return 0;
}

static int pkt_start(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf)
{
printf("PKT_START !!!\n");
    return 0;
}

static int pkt_data(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
printf("PKT_DATA !!!\n");
    return 0;
}

static int pkt_respok(jail_packet_ctx *ctx, jail_packet *pkt,
                      event_buf *write_buf)
{
printf("PKT_RESPOK !!!\n");
    return 0;
}

static int pkt_resperr(jail_packet_ctx *ctx, jail_packet *pkt,
                       event_buf *write_buf)
{
printf("PKT_RESPERR !!!\n");
    return 0;
}

static int jail_packet_forward(event_ctx *ctx, event_buf *buf, void *user_data)
{
    jail_packet_ctx *pkt_ctx = (jail_packet_ctx *) user_data;
    jail_packet *pkt;
    event_buf wbuf;
    ssize_t pkt_siz;
    off_t pkt_off = 0;

    (void) ctx;

    event_buffer_to(buf, &wbuf);
    while (1) {
        pkt_siz = pkt_header_read((unsigned char *) buf->buf + pkt_off,
                                  buf->buf_used);
        if (pkt_siz < 0) {
            /* invalid jail packet */
            ctx->active = 0;
            return 0;
        }
        pkt = (jail_packet *)(buf->buf + pkt_off);

        if (jpc[pkt->type].pc &&
            jpc[pkt->type].pc(pkt_ctx, pkt, &wbuf))
        {
            pkt_ctx->pstate = JP_INVALID;
            break;
        }

        pkt_off += pkt_siz;
        buf->buf_used -= pkt_siz;
    }

    if (pkt_off)
        memmove(buf->buf, buf->buf + pkt_off, buf->buf_used);

    if (event_buf_drain(&wbuf) < 0)
        pkt_ctx->pstate = JP_INVALID;

    if (pkt_ctx->pstate == JP_NONE || pkt_ctx->pstate == JP_INVALID)
        ctx->active = 0;

    return 1;
}

int jail_packet_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    assert(ctx && pkt_ctx);
    assert(pkt_ctx->pstate == JP_HANDSHAKE);

    pkt_ctx->pstate = JP_DATA;

    return event_loop(ctx, jail_packet_forward, pkt_ctx);
}

static int jail_handshake_handler(event_ctx *ctx, event_buf *buf, void *user_data)
{
printf("JAIL HANDSHAKE HANDLER !!\n");
    return 0;
}

event_ctx *jail_client_handshake(int server_fd, jail_packet_ctx *pkt_ctx)
{
    event_ctx *ev_ctx = NULL;
    event_buf write_buf = WRITE_BUF(server_fd);
    size_t user_len, pass_len;

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
    pkt_ctx->is_valid = 1;

    if (event_loop(ev_ctx, jail_handshake_handler, pkt_ctx)) {
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

printf("_server_handshake_\n");
    return event_loop(ctx, jail_packet_forward, pkt_ctx);
}
