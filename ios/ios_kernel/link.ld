OUTPUT_ARCH(arm)

INCLUDE "imports.ld"

SECTIONS {
    . = (0x08135000);

    .text : {
        crt0.o(.init);
        *(.text*);
    }
    .rodata : {
        *(.rodata*);
    }
    .data : {
        *(.data*);
    }
    /* .bss : {
        *(.bss*);
    } */

    /DISCARD/ : {
        *(*);
    }
}

/* make sure we don't go over mapped memory  */
ASSERT((SIZEOF(.text) + SIZEOF(.rodata) + SIZEOF(.data) /*+ SIZEOF(.bss)*/) < 0x2000, "arm_kernel is too big");
