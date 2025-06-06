    .syntax unified

#include "version.h"

    .section .header, "a"

    .type g_header, %object
    .size g_header, .-g_header

g_header:
    .byte 'T','R','Z','F'            // magic
    .word reset_handler              // reset handler,  replace later with : .word g_header_end - g_header    // hdrlen
    .word 0                          // expiry
    .word _codelen                   // codelen
    .byte VERSION_MAJOR              // vmajor
    .byte VERSION_MINOR              // vminor
    .byte VERSION_PATCH              // vpatch
    .byte 0                          // vbuild
    .byte FIX_VERSION_MAJOR          // fix_vmajor
    .byte FIX_VERSION_MINOR          // fix_vminor
    .byte FIX_VERSION_PATCH          // fix_vpatch
    .byte 0                          // fix_vbuild
    .word HW_MODEL                   // type of the designated hardware
    .byte HW_REVISION                // revision of the designated hardware
    .byte 0                          // monotonic version placeholder - not used in legacy
    . = . + 2                        // reserved
    . = . + 512                      // hash1 ... hash16
    . = . + 64                       // sig1
    . = . + 64                       // sig2
    . = . + 64                       // sig3
    . = . + 64                       // sig4
    .byte 0                          // sigindex1
    .byte 0                          // sigindex2
    .byte 0                          // sigindex3
    .byte 0                          // sigindex4
    . = . + 151                      // reserved
    .byte ONEKEY_VER_MAJOR           // onekey major
    .byte ONEKEY_VER_MINOR           // onekey minor
    .byte ONEKEY_VER_PATCH           // onekey patch
    .byte 0                          //
    . = . + 65                       // reserved
g_header_end:
