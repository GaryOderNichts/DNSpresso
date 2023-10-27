#pragma once

#include <stdint.h>

/* IPC message */
typedef struct ipcmessage {
    uint32_t command;
    uint32_t result;
    uint32_t fd;
    uint32_t flags;
    uint32_t client_cpu;
    uint32_t client_pid;
    uint64_t client_gid;
    uint32_t server_handle;

    union {
        uint32_t args[5];

        struct {
            char *device;
            uint32_t mode;
            uint32_t resultfd;
        } open;

        struct {
            void *data;
            uint32_t length;
        } read, write;

        struct {
            uint32_t offset;
            uint32_t origin;
        } seek;

        struct {
            uint32_t command;

            uint32_t *buffer_in;
            uint32_t length_in;
            uint32_t *buffer_io;
            uint32_t length_io;
        } ioctl;
        struct _ioctlv {
            uint32_t command;

            uint32_t num_in;
            uint32_t num_io;
            struct _ioctlv *vector;
        } ioctlv;
    };

    uint32_t prev_command;
    uint32_t prev_fd;
    uint32_t virt0;
    uint32_t virt1;
} __attribute__((packed)) ipcmessage;

typedef struct {
    unsigned char unk[0x10];

    unsigned int pos;
    int type;
    unsigned int cafe_pid;

    unsigned char unk2[0xC];

    char name[0x40];

    unsigned char unk3[0x12D8 - 0x68];
} MCPLoadFileRequest;

typedef struct __attribute__((packed)) {
    uint32_t group;
    uint64_t mask;
} Permission;

typedef struct __attribute__((packed)) {
    uint32_t version;
    char unkn1[8];
    uint64_t titleId;
    uint32_t groupId;
    uint32_t cmdFlags;
    char argstr[4096];
    char* argv[64];
    uint32_t max_size;
    uint32_t avail_size;
    uint32_t codegen_size;
    uint32_t codegen_core;
    uint32_t max_codesize;
    uint32_t overlay_arena;
    uint32_t num_workarea_heap_blocks;
    uint32_t num_codearea_heap_blocks;
    Permission permissions[19];
    uint32_t default_stack0_size;
    uint32_t default_stack1_size;
    uint32_t default_stack2_size;
    uint32_t default_redzone0_size;
    uint32_t default_redzone1_size;
    uint32_t default_redzone2_size;
    uint32_t exception_stack0_size;
    uint32_t exception_stack1_size;
    uint32_t exception_stack2_size;
    uint32_t sdkVersion;
    uint32_t titleVersion;
    char unknwn2[0x1270 - 0x124C];
} MCPPPrepareTitleInfo;
