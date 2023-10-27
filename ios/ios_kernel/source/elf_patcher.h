/***************************************************************************
 * Copyright (C) 2016
 * by Dimok
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any
 * damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it and
 * redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you
 * must not claim that you wrote the original software. If you use
 * this software in a product, an acknowledgment in the product
 * documentation would be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and
 * must not be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source
 * distribution.
 ***************************************************************************/
#ifndef _ELF_PATCHER_H
#define _ELF_PATCHER_H

#include <stdint.h>
#include <string.h>

#define ARM_B(addr, func)    (0xEA000000 | ((((uint32_t) (func) - (uint32_t) (addr) -8) >> 2) & 0x00FFFFFF)) // +-32MB
#define ARM_BL(addr, func)   (0xEB000000 | ((((uint32_t) (func) - (uint32_t) (addr) -8) >> 2) & 0x00FFFFFF)) // +-32MB
#define THUMB_B(addr, func)  ((0xE000 | ((((uint32_t) (func) - (uint32_t) (addr) -4) >> 1) & 0x7FF)))        // +-2KB
#define THUMB_BL(addr, func) ((0xF000F800 | ((((uint32_t) (func) - (uint32_t) (addr) -4) >> 1) & 0x0FFF)) | ((((uint32_t) (func) - (uint32_t) (addr) -4) << 4) & 0x7FFF000)) // +-4MB

typedef struct {
    uint32_t address;
    void *data;
    uint32_t size;
} patch_table_t;

void section_write(uint32_t ios_elf_start, uint32_t address, const void *data, uint32_t size);

void section_write_bss(uint32_t ios_elf_start, uint32_t address, uint32_t size);

static inline void section_write_word(uint32_t ios_elf_start, uint32_t address, uint32_t word) {
    section_write(ios_elf_start, address, &word, sizeof(word));
}


static inline void patch_table_entries(uint32_t ios_elf_start, const patch_table_t *patch_table, uint32_t patch_count) {
    uint32_t i;
    for (i = 0; i < patch_count; i++) {
        section_write(ios_elf_start, patch_table[i].address, patch_table[i].data, patch_table[i].size);
    }
}


#endif
