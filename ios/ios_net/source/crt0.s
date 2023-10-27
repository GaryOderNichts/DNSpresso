.section ".init"
.arm
.align 4

.extern _main
.type _main, %function

_start:
    bl _main

    // load the threadQuitRoutine into lr
    ldr lr, =0x08134000

    // load the original stack pointer
    ldr sp, =0x1250E050
    
    // jump back into the inet timer thread
    ldr pc, =0x12301228
