// +build amd64

// Assembly implementations for CPUID, RDRAND, and RDSEED on AMD64.

#include "textflag.h"

// func cpuid(eaxIn, ecxIn uint32) (eax, ebx, ecx, edx uint32)
TEXT ·cpuid(SB), NOSPLIT, $0-24
    MOVL    eaxIn+0(FP), AX
    MOVL    ecxIn+4(FP), CX
    CPUID
    MOVL    AX, eax+8(FP)
    MOVL    BX, ebx+12(FP)
    MOVL    CX, ecx+16(FP)
    MOVL    DX, edx+20(FP)
    RET

// func rdrand64() (uint64, bool)
// RDRAND stores a random value in the destination register and sets CF=1 on success.
TEXT ·rdrand64(SB), NOSPLIT, $0-16
    // RDRAND RAX - instruction encoding 0x48 0x0F 0xC7 0xF0
    BYTE    $0x48
    BYTE    $0x0F
    BYTE    $0xC7
    BYTE    $0xF0
    JCC     rdrand_fail     // Jump if carry flag is clear (failure)
    MOVQ    AX, ret+0(FP)
    MOVB    $1, ret+8(FP)
    RET
rdrand_fail:
    MOVQ    $0, ret+0(FP)
    MOVB    $0, ret+8(FP)
    RET

// func rdseed64() (uint64, bool)
// RDSEED stores a random value in the destination register and sets CF=1 on success.
TEXT ·rdseed64(SB), NOSPLIT, $0-16
    // RDSEED RAX - instruction encoding 0x48 0x0F 0xC7 0xF8
    BYTE    $0x48
    BYTE    $0x0F
    BYTE    $0xC7
    BYTE    $0xF8
    JCC     rdseed_fail     // Jump if carry flag is clear (failure)
    MOVQ    AX, ret+0(FP)
    MOVB    $1, ret+8(FP)
    RET
rdseed_fail:
    MOVQ    $0, ret+0(FP)
    MOVB    $0, ret+8(FP)
    RET
