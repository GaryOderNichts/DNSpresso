.section ".init"
.arm
.align 4

.extern mcp_main
.type mcp_main, %function

_start:
    mov r11, r0
    push {r0-r11, lr}

    bl mcp_main

    pop {r0-r11, pc}
