#pragma once

#include <assert.h>
#include <stdint.h>

#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif

#ifndef CHECK_SIZE
#define CHECK_SIZE(type, size) static_assert(sizeof(type) == size, #type " must be " #size " bytes")
#endif

typedef struct dns_ios_reply dns_ios_reply;
typedef struct dns_querys dns_querys;

struct hostent {
    char* h_name;
    char** h_aliases;
    int32_t h_addrtype;
    int32_t h_length;
    char** h_addr_list;
};
CHECK_SIZE(struct hostent, 0x14);

struct dns_ios_reply {
    void* request;
    dns_ios_reply* next;
};
CHECK_SIZE(dns_ios_reply, 0x8);

struct dns_querys {
    dns_querys* next;
    uint32_t unk0x4;
    uint32_t send_time;
    uint32_t expire_time;
    uint16_t tries;
    uint16_t lport;
    uint16_t id;
    uint16_t server_index;
    uint32_t fhost;
    int32_t replies;
    int32_t ipaddrs;
    uint32_t ipaddr_list[10];
    char* addrptrs[10];
    int32_t err;
    int32_t r_code;
    char dns_names[256];
    char ptr_name[256];
    uint32_t auths_ip;
    char* alist[4];
    struct hostent hostent;
    uint8_t type;
    uint8_t padding0x2a5[3];
    uint32_t unused0x2a8;
    uint32_t unused0x2ac;
    dns_ios_reply ios_reply;
    void* ios_ptr;
    void* dns_request_buf;
    void* tcp_socket;
    uint32_t tcp_send_offset;
    void* tcp_dns_buf;
    uint32_t tcp_dns_buf_size;
    uint32_t alloc_time;
    dns_querys* tcp_queue_next;
    dns_querys** tcp_queue_start;
    uint8_t flags;
    uint8_t padding0x2dd[3];
};
CHECK_SIZE(dns_querys, 0x2e0);
