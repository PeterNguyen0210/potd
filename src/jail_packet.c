#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "jail_packet.h"
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

typedef struct jail_packet_creds {
    uint16_t user_siz;
    uint16_t pass_siz;
    /* char username[user_size] */
    /* char password[user_size] */
} JP_ATTRS jail_packet_creds;

typedef int (*packet_callback)(jail_packet_ctx *ctx, jail_packet *pkt,
                               event_buf *write_buf);

typedef struct jail_packet_callback {
    uint8_t type;
    packet_callback pc;
} jail_packet_callback;

static ssize_t pkt_header_read(unsigned char *buf, size_t siz);
static int pkt_hello(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf);
static int jail_event_loop(event_ctx *ctx, event_buf *buf, void *user_data);
static int jail_handshake_event_loop(event_ctx *ctx, event_buf *buf, void *user_data);

#define PKT_CB(type, cb) \
    { type, cb }
static const jail_packet_callback jpc[] = {
    PKT_CB(PKT_INVALID, NULL),
    PKT_CB(PKT_HELLO,   pkt_hello)
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

static int pkt_header_write(unsigned char *buf, size_t siz)
{
    jail_packet *pkt;

    if (siz < sizeof(*pkt))
        return 1;
    pkt = (jail_packet *) buf;

    if (pkt->type >= SIZEOF(jpc))
        return 1;

    pkt->size = htons(pkt->size);
    if (siz != PKT_SIZ(pkt))
        return 1;

    return 0;
}

static int pkt_hello(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf)
{
    jail_packet_hello *pkt_hello;

    pkt_hello = (jail_packet_hello *) PKT_SUB(pkt);
    pkt_hello->magic1 = ntohl(pkt_hello->magic1);
    pkt_hello->magic2 = ntohl(pkt_hello->magic2);
    if (pkt_hello->magic1 != JP_MAGIC1 ||
        pkt_hello->magic2 != JP_MAGIC2)
    {
        return 1;
    }

    if (ctx->is_server) {
        if (event_buf_fill(write_buf, (unsigned char *) pkt, PKT_SIZ(pkt)))
            return 1;
    }

    return 0;
}

static int jail_event_loop(event_ctx *ctx, event_buf *buf, void *user_data)
{
    jail_packet_ctx *pkt_ctx = (jail_packet_ctx *) user_data;
    jail_packet *pkt;
    event_buf wbuf = { buf->fd, {0}, 0, buf->buf_user_data };
    ssize_t pkt_siz;
    off_t pkt_off = 0;

    (void) ctx;

    while (1) {
        pkt_siz = pkt_header_read((unsigned char *) buf->buf + pkt_off,
                                  buf->buf_used);
        if (pkt_siz < 0)
            break;
        pkt = (jail_packet *)(buf->buf + pkt_off);

        if (jpc[pkt->type].pc &&
            jpc[pkt->type].pc(pkt_ctx, pkt, &wbuf))
        {
            pkt_ctx->pstate = JP_INVALID;
            break;
        }

        pkt_off += pkt_siz;
        buf->buf_used -= pkt_off;
    }

    if (pkt_off)
        memmove(buf->buf, buf->buf + pkt_off, buf->buf_used);

    if (event_buf_drain(&wbuf) < 0)
        pkt_ctx->pstate = JP_INVALID;

    return pkt_ctx->pstate != JP_NONE && pkt_ctx->pstate != JP_INVALID;
}

int jail_packet_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    assert(ctx && pkt_ctx);
    assert(pkt_ctx->on_data && pkt_ctx->user_data);

    assert(pkt_ctx->pstate == JP_HANDSHAKE);
    pkt_ctx->pstate = JP_DATA;

    return event_loop(ctx, jail_event_loop, pkt_ctx);
}

static int jail_handshake_event_loop(event_ctx *ctx, event_buf *buf, void *user_data)
{
    (void) ctx;
    (void) buf;
    (void) user_data;

    return 0;
}

int jail_packet_handshake(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    assert(ctx && pkt_ctx);
    assert(pkt_ctx->on_data && pkt_ctx->user_data);

    pkt_ctx->pstate = JP_HANDSHAKE;

    return event_loop(ctx, jail_handshake_event_loop, pkt_ctx);
}
