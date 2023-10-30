#include "imports.h"
#include "ipc.h"
#include "thread.h"
#include "elf_patcher.h"

#include <stdio.h>

#include "../../dns_types.h"
#include "../../ios_net/ios_net.bin.h"
#include "../../ios_mcp/ios_mcp.bin.h"
#include "../../ios_mcp/ios_mcp_syms.h"

static const uint8_t repairData_set_fault_behavior[] = {
    0xE1,0x2F,0xFF,0x1E,0xE9,0x2D,0x40,0x30,0xE5,0x93,0x20,0x00,0xE1,0xA0,0x40,0x00,
    0xE5,0x92,0x30,0x54,0xE1,0xA0,0x50,0x01,0xE3,0x53,0x00,0x01,0x0A,0x00,0x00,0x02,
    0xE1,0x53,0x00,0x00,0xE3,0xE0,0x00,0x00,0x18,0xBD,0x80,0x30,0xE3,0x54,0x00,0x0D,
};

static const uint8_t repairData_set_panic_behavior[] = {
    0x08,0x16,0x6C,0x00,0x00,0x00,0x18,0x0C,0x08,0x14,0x40,0x00,0x00,0x00,0x9D,0x70,
    0x08,0x16,0x84,0x0C,0x00,0x00,0xB4,0x0C,0x00,0x00,0x01,0x01,0x08,0x14,0x40,0x00,
    0x08,0x15,0x00,0x00,0x08,0x17,0x21,0x80,0x08,0x17,0x38,0x00,0x08,0x14,0x30,0xD4,
    0x08,0x14,0x12,0x50,0x08,0x14,0x12,0x94,0xE3,0xA0,0x35,0x36,0xE5,0x93,0x21,0x94,
    0xE3,0xC2,0x2E,0x21,0xE5,0x83,0x21,0x94,0xE5,0x93,0x11,0x94,0xE1,0x2F,0xFF,0x1E,
    0xE5,0x9F,0x30,0x1C,0xE5,0x9F,0xC0,0x1C,0xE5,0x93,0x20,0x00,0xE1,0xA0,0x10,0x00,
    0xE5,0x92,0x30,0x54,0xE5,0x9C,0x00,0x00,
};

void mcp_run_patches(uint32_t ios_elf_start)
{
    // write ios_mcp code and bss
    section_write_bss(ios_elf_start, __mcp_bss_start, __mcp_bss_end - __mcp_bss_start);
    section_write(ios_elf_start, 0x05116000, ios_mcp, ios_mcp_size);

    // hook mcp main
    section_write_word(ios_elf_start, 0x05056718, ARM_BL(0x05056718, __mcp_text_start));

    // write the loadfile and cos permission patches
    section_write_word(ios_elf_start, 0x050254D6, THUMB_BL(0x050254D6, MCP_LoadFile_patch));
    section_write_word(ios_elf_start, 0x0501dd78, THUMB_BL(0x0501dd78, MCP_ReadCOSXml_patch));
    section_write_word(ios_elf_start, 0x051105ce, THUMB_BL(0x051105ce, MCP_ReadCOSXml_patch));
}

void kernel_launch_ios(uint32_t launch_address, uint32_t L, uint32_t C, uint32_t H)
{
    void (*kernel_launch_bootrom)(uint32_t launch_address, uint32_t L, uint32_t C, uint32_t H) = (void *) 0x0812A050;

    //IOS_Shutdown(1);

    if (*(uint32_t *) (launch_address - 0x300 + 0x1AC) == 0x00DFD000) {
        int level = disable_interrupts();
        uint32_t control_register = disable_mmu();

        uint32_t ios_elf_start = launch_address + 0x804 - 0x300;
        mcp_run_patches(ios_elf_start);

        restore_mmu(control_register);
        enable_interrupts(level);
    }

    kernel_launch_bootrom(launch_address, L, C, H);
}

dns_querys* find_dns_query_by_request(void* request)
{
    dns_querys* query = *(dns_querys**)0x12791f6c;
    while (query) {
        dns_ios_reply* dns_reply = &query->ios_reply;
        while (dns_reply) {
            if (dns_reply->request == request) {
                return query;
            }

            dns_reply = dns_reply->next;
        }

        query = query->next;
    }

    return NULL;
}

int syslog_write(const char* fmt, ...)
{
    static int syslog_handle = -4;
    if (syslog_handle < 0) {
        syslog_handle = IOS_Open("/dev/syslog", 0);
        if (syslog_handle < 0) {
            return -4;
        }
    }

    char* buf = (char*) IOS_HeapAlloc(0xcaff, 0x120);
    if (!buf) {
        return -4;
    }

    va_list args;
    va_start(args, fmt);
    int res = vsnprintf(buf, 0x120, fmt, args);
    va_end(args);

    if (res < 1) {
        return -4;
    }

    res = IOS_Write(syslog_handle, buf, res);
    IOS_HeapFree(0xcaff, buf);
    return res;
}

IpcRequest* _main()
{
    int level = disable_interrupts();
    uint32_t control_register = disable_mmu();

    // patch kernel thread stack check
    *(volatile uint32_t*) 0x0812c138 = 0xe3a00000; // mov r0, #0
    *(volatile uint32_t*) 0x0812c13c = 0xe12fff1e; // bx lr

    // load ios_net recover code
    memcpy((void*) 0x12431900, ios_net, ios_net_size);

    // load ios_mcp code and clear bss
    memcpy((void*) (0x05116000 - 0x05100000 + 0x13D80000), ios_mcp, ios_mcp_size);
    memset((void*) (__mcp_bss_start - 0x05074000 + 0x08234000), 0, __mcp_bss_end - __mcp_bss_start);

    // restore overwritten memory
    memcpy((void*) 0x081298bc, repairData_set_fault_behavior, sizeof(repairData_set_fault_behavior));
    memcpy((void*) 0x081296e4, repairData_set_panic_behavior, sizeof(repairData_set_panic_behavior));

    // map free kernel memory
    ios_map_shared_info_t map_info;
    map_info.paddr = 0x08135000;
    map_info.vaddr = 0x08135000;
    map_info.size = 0x2000;
    map_info.domain = 0; // KERNEL
    map_info.type = 3;
    map_info.cached = 0xffffffff;
    _iosMapSharedUserExecution(&map_info);

    // map the mcp sections
    map_info.paddr  = 0x050bd000 - 0x05000000 + 0x081c0000;
    map_info.vaddr  = 0x050bd000;
    map_info.size   = 0x3000;
    map_info.domain = 1; // MCP
    map_info.type   = 3;
    map_info.cached = 0xffffffff;
    _iosMapSharedUserExecution(&map_info);

    map_info.paddr  = 0x05116000 - 0x05100000 + 0x13d80000;
    map_info.vaddr  = 0x05116000;
    map_info.size   = 0xa000;
    map_info.domain = 1; // MCP
    map_info.type   = 3;
    map_info.cached = 0xffffffff;
    _iosMapSharedUserExecution(&map_info);

    // apply IOS ELF launch hook necessary to apply patches for replacing relaunch title
    *(volatile uint32_t*) 0x0812A120 = ARM_BL(0x0812A120, kernel_launch_ios);

    // add mcp ioctl hook to trigger relaunch
    *(volatile uint32_t*) (0x05025242 - 0x05000000 + 0x081c0000) = THUMB_BL(0x05025242, MCP_ioctl100_patch);

    // reenable mmu
    restore_mmu(control_register);

    // invalidate all cache
    invalidate_dcache(NULL, 0x4001);
    invalidate_icache();

    // restore interrupts
    enable_interrupts(level);

    syslog_write("DNSpresso: kernel code running!\n");

    // give the current thread full access to MCP for triggering the title relaunch
    setClientCapabilities(currentThreadContext->pid, 0xd, 0xffffffffffffffffllu);

    // Since we trashed the pointer to the ipc reply, we need to find it again
    // otherwise we won't be able to reply to it and callee is stuck forever

    // TODO this currently relies on only having one pending ioctlv,
    //      per dns_query which might not always be the case

    ResourceManager* socketResourceManager = NULL;
    int res = findResourceManager("/dev/socket", &socketResourceManager);
    if (res < 0 || !socketResourceManager) {
        syslog_write("DNSpresso: failed to find socket resource manager!\n");
        return NULL;
    }

    // Iterate over all resource requests belonging to the socket resource manager
    for (int i = 0; i < 256; i++) {
        ResourceRequest* req = &resourceRequestList.resourceRequests[i];
        if (req->resourceManager == socketResourceManager && req->requestData.command == 7 && req->requestData.args[0] == 0x26) {
            syslog_write("DNSpresso: found sm_dns_query_type request from pid %d\n", req->resourceHandleManager->pid);

            // make sure this request doesn't have a valid dns query
            if (!find_dns_query_by_request(&req->requestData)) {
                syslog_write("DNSpresso: found non-matching dns_reply\n");
                return &req->requestData;
            }
        }
    }

    return NULL;
}
