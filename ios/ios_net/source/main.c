#include <stdio.h>

void IOS_Shutdown(int reset);
int IOS_Open(const char* device, int mode);
int IOS_Close(int fd);
int IOS_Ioctl(int fd, int request, void* inBuf, int inLen, void* outBuf, int outLen);
int IOS_ResourceReply(void* request, int result);

extern int currentNetThread;

void _main(void* request)
{
    printf("DNSpresso: Hello from ios_net code, request %p!\n", request);

    currentNetThread = -1;

    if (request) {
        IOS_ResourceReply(request, 0);
    }

    // trigger title relaunch
    int mcpHandle = IOS_Open("/dev/mcp", 0);
    if (mcpHandle > 0) {
        printf("DNSpresso: Calling mcp hook\n");
        IOS_Ioctl(mcpHandle, 100, NULL, 0, NULL, 0);

        IOS_Close(mcpHandle);
    } else {
        printf("DNSpresso: Cannot open MCP: %x\n", mcpHandle);
    }
}
