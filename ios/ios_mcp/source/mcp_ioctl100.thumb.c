#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

extern uint64_t currentColdbootOS;
extern uint64_t currentColdbootTitle;

int (*const locateTitle)(uint32_t titleId_hi, uint32_t titleId_lo, uint64_t* os_id, int param_4) = (void*) (0x0502acb8 | 1);
int (*const shellCommand_title_launch)(int argc, char** argv) = (void*) (0x0510c9a0 | 1);

// Hook ioctl100 and trigger a title launch into the deafult title
int __attribute__((used)) MCP_ioctl100_patch()
{
    printf("DNSpresso: MCP_ioctl100_patch\n");
    printf("DNSpresso: title0x%016llx os 0x%016llx\n", currentColdbootTitle, currentColdbootOS);

    // This triggers a full cafe relaunch into the specified title
    // not entirely sure how shell commands handle these args but this seems to work
    int argc = 2;
    char* argv[] = {
        "",
        "",
        (char*) (uint32_t) (currentColdbootTitle >> 32),
        (char*) (uint32_t) (currentColdbootTitle & 0xffffffff),
    };
    int res = shellCommand_title_launch(argc, argv);
    printf("DNSpresso: shellCommand_title_launch: %d\n", res);

    return 4;
}
