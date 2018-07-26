#ifndef POTD_JAIL_PROTOCOL_H
#define POTD_JAIL_PROTOCOL_H 1

#include <stdlib.h>
#include <stdint.h>

#include "jail.h"
#include "pevent.h"

#define USER_LEN 255
#define PASS_LEN 255

#define PROTO_TIMEOUT 1000
#define PROTO_MAGIC 0xdeadc0de
#define PROTO_TYPE_USER 0x41414141
#define PROTO_TYPE_PASS 0x42424242
#define PROTO_TYPE_DATA 0x43434343

typedef struct __attribute__((packed, aligned(4))) jail_data {
    int used;
    uint32_t last_type;
    char user[USER_LEN+1];
    char pass[PASS_LEN+1];
} jail_data;

typedef struct jail_protocol_hdr {
    uint32_t magic;
    uint32_t type;
    uint32_t size;
} jail_protocol_hdr;


ssize_t jail_protocol_readhdr(jail_data *dst, unsigned char *buf,
                              size_t bufsiz);

ssize_t jail_protocol_writehdr(int type, unsigned char *buf, size_t bufsiz);

int jail_protocol_handshake_read(event_ctx *ev_client, int client_fd,
                                 int tty_fd, jail_data *dst);

int jail_protocol_handshake_write(event_ctx *ev_server, int server_fd,
                                  int proto_fd, jail_data *dst);

int jail_protocol_loop(event_ctx *ctx, on_event_cb on_event, void *user_data);

#endif
