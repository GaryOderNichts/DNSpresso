#include "imports.h"
#include "gfx.h"

const char* coffee[] = {
    " ( (",
    "  ) )",
    "........",
    "|      |]",
    "\\      /",
    " `----'",
};

void __attribute__((used)) mcp_main(void)
{
    gfx_clear(0x000000ff);

    int yoff = 16;
    gfx_print(16, yoff, 0, "DNSpresso by GaryOderNichts");
    yoff += 8 + 4;

    for (uint32_t i = 0; i < sizeof(coffee) / sizeof(char*); i++) {
        gfx_print(16, yoff, 0, coffee[i]);
        yoff += 8 + 4;
    }
    yoff += 8 + 4;

    gfx_print(16, yoff, 0, "Please wait...");
    yoff += 8 + 4;
}
