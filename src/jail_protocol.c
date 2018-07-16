/*
 * jail_protocol.c
 * potd is licensed under the BSD license:
 *
 * Copyright (c) 2018 Toni Uhlig <matzeton@googlemail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - Neither the name of the Yellow Lemon Software nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "jail_protocol.h"
#include "utils.h"

typedef struct jail_event {
    jail_data *data;
    int sock_fd;
    int tty_fd;
} jail_event;

static int
handshake_read_loop(event_ctx *ev_ctx, int src_fd, void *user_data);


ssize_t jail_protocol_readhdr(jail_data *dst, unsigned char *buf,
                              size_t bufsiz)
{
    jail_protocol_hdr *hdr;
    size_t data_siz, min_siz;

    assert(dst);

    if (bufsiz < sizeof(*hdr))
        return -1;
    hdr = (jail_protocol_hdr *) buf;
    if (ntohl(hdr->magic) != PROTO_MAGIC)
        return -1;
    data_siz = bufsiz - sizeof(*hdr);
    if (ntohl(hdr->size) != data_siz)
        return -1;

    switch (ntohl(hdr->type)) {
        case PROTO_TYPE_USER:
            min_siz = MIN(data_siz, USER_LEN);
            memcpy(dst->user, (char *) buf + sizeof(*hdr), min_siz);
            dst->user[min_siz] = 0;
            break;
        case PROTO_TYPE_PASS:
            min_siz = MIN(data_siz, PASS_LEN);
            memcpy(dst->pass, (char *) buf + sizeof(*hdr), min_siz);
            dst->pass[min_siz] = 0;
            break;
        case PROTO_TYPE_DATA:
            break;
        default:
            break;
    }

    return data_siz;
}

ssize_t jail_protocol_writehdr(jail_protocol_hdr *src, int type,
							   unsigned char *buf, size_t bufsiz)
{
    jail_protocol_hdr *hdr;
    size_t data_siz;

    assert(src && buf);

    hdr = (jail_protocol_hdr *) buf;
    hdr->magic = htonl(PROTO_MAGIC);
    hdr->type = htonl(type);
    data_siz = bufsiz - sizeof(*hdr);
    hdr->size = data_siz;

    return data_siz;
}

static int
handshake_read_loop(event_ctx *ev_ctx, int src_fd, void *user_data)
{
    jail_event *ev_jail = (jail_event *) user_data;
    int siz, rc, dst_fd;
    unsigned char buf[BUFSIZ] = {0};

    (void) ev_ctx;

    if (src_fd == ev_jail->sock_fd)
        dst_fd = ev_jail->tty_fd;
    else if (src_fd == ev_jail->tty_fd)
        dst_fd = ev_jail->sock_fd;
    else
        goto error;

    siz = read(src_fd, buf, sizeof buf);
    if (siz <= 0)
        goto error;
    rc = jail_protocol_readhdr(ev_jail->data, buf, sizeof buf);
    if (rc < 0) {
        rc = write(dst_fd, buf, siz);
        goto error;
    }

    return 1;
error:
    ev_ctx->active = 0;
    return 1;
}

int jail_protocol_handshake_read(event_ctx *ev_client, int client_fd,
                                 int tty_fd, jail_data *dst)
{
    jail_event ev_jail = {0,0,0};
    int rc;

    ev_jail.data = dst;
    ev_jail.sock_fd = client_fd;
    ev_jail.tty_fd = tty_fd;
    rc = event_loop(ev_client, handshake_read_loop, &ev_jail);

    return rc || !ev_client->active;
}
