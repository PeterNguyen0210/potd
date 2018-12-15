/*
 * jail_packet.h
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
 * - The names of its contributors may not be used to endorse or promote
 *   products derived from this
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

#ifndef POTD_JAIL_PACKET_H
#define POTD_JAIL_PACKET_H 1

#include <stdint.h>

#include "pevent.h"

#define INIT_PKTCTX(callback, user_data) \
    { 0, JC_CLIENT, JP_NONE, NULL, NULL }

#define PKT_INVALID 0x0 /* should not happen, otherwise error */
/* Client: jail_packet(PKT_HELLO)) + jail_packet_hello
 * Server: jail_packet(RESP_*)
 */
#define PKT_HELLO   0x1
#define PKT_USER    0x2
#define PKT_PASS    0x3
#define PKT_START   0x4
#define PKT_DATA    0x5
#define PKT_RESPOK  0x6
#define PKT_RESPERR 0x7

typedef enum jail_packet_state {
    JP_INVALID = 0, JP_NONE, JP_HANDSHAKE, JP_DATA
} jail_packet_state;

typedef enum jail_ctx_type {
    JC_INVALID = 0, JC_CLIENT, JC_SERVER
} jail_ctx_type;

#define USER_LEN 255
#define PASS_LEN 255

typedef struct jail_packet_ctx {
    int is_valid;

    jail_ctx_type ctype;
    jail_packet_state pstate;

    char *user;
    char *pass;
} jail_packet_ctx;


int jail_packet_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx);

event_ctx *jail_client_handshake(int server_fd, jail_packet_ctx *pkt_ctx);

int jail_server_handshake(event_ctx *ctx, jail_packet_ctx *pkt_ctx);

#endif
