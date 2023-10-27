#pragma once

#include <assert.h>
#include <stdint.h>

#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif

#ifndef CHECK_SIZE
#define CHECK_SIZE(type, size) static_assert(sizeof(type) == size, #type " must be " #size " bytes")
#endif

typedef struct ResourceManager ResourceManager;
typedef struct ResourceHandleManager ResourceHandleManager;
typedef struct ResourceHandle ResourceHandle;
typedef struct ClientCapability ClientCapability;
typedef struct IpcRequest IpcRequest;
typedef struct ResourceRequest ResourceRequest;
typedef struct ResourceRequestList ResourceRequestList;

struct ResourceManager {
    char deviceName[32];
    int32_t messageQueue;
    ResourceHandleManager* resourceHandleManager;
    int32_t permissionGroup;
    uint16_t deviceNameLen;
    uint16_t firstRequest;
    uint16_t lastRequest;
    uint16_t numRequests;
    uint16_t numHandles;
    int16_t nextResourceManager;
    int16_t previousResourceManager;
    uint16_t unk0x3a;
    uint16_t maxVectors;
    uint16_t unk0x3e;
};
CHECK_SIZE(ResourceManager, 0x40);

struct ResourceHandle {
    int32_t handle;
    int32_t id;
    ResourceManager* resourceManager;
    uint8_t state;
    uint8_t padding[3];
};
CHECK_SIZE(ResourceHandle, 0x10);

struct ClientCapability {
    int32_t featureId;
    uint32_t mask_hi;
    uint32_t mask_lo;
};
CHECK_SIZE(ClientCapability, 0xc);

struct ResourceHandleManager {
    uint32_t titleId_hi;
    uint32_t titleId_lo;
    uint32_t gid;
    uint32_t pid;
    uint32_t numResourceHandles;
    uint32_t mostResourceHandles;
    uint32_t maxResourceHandles;
    ResourceHandle resourceHandles[96];
    uint32_t numResourceRequests;
    uint32_t mostResourceRequests;
    uint32_t failedRegisterMaxResourceRequests;
    uint32_t maxResourceRequests;
    ClientCapability clientCapablities[20];
    uint32_t numResourceManagers;
    uint32_t maxResourceManagers;
    uint32_t failedResourceReplies;
};
CHECK_SIZE(ResourceHandleManager, 0x728);

struct IpcRequest {
    int32_t command;
    int32_t reply;
    int32_t handle;
    uint32_t flags;
    uint32_t cpuId;
    uint32_t pid;
    uint32_t titleId_hi;
    uint32_t titleId_lo;
    uint32_t gid;
    uint32_t args[5];
};
CHECK_SIZE(IpcRequest, 0x38);

struct ResourceRequest {
    IpcRequest requestData;
    void* messageQueue;
    int32_t messageQueueId;
    IpcRequest* ipcRequest;
    ResourceHandleManager* resourceHandleManager;
    ResourceManager* resourceManager;
    int32_t resourceHandleId;
    uint16_t nextIdx;
    uint16_t prevIdx;
    uint8_t unk[96];
};

struct ResourceRequestList {
    uint16_t numRegistered;
    uint16_t mostRegistered;
    uint16_t failedRegistered;
    int16_t firstFreeIdx;
    int16_t lastFreeIdx;
    uint16_t padding;
    ResourceRequest resourceRequests[256];
};

extern ResourceRequestList resourceRequestList;

ResourceHandleManager* getResourceHandleManager(uint32_t pid);

int findResourceManager(const char* device, ResourceManager** outResourceManager);
