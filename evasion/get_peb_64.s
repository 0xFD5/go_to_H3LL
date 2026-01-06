//go:build amd64
#include "textflag.h"
TEXT ·GetPEB(SB), NOSPLIT, $0-8
    MOVQ 0x60(GS), AX
    MOVQ AX, ret+0(FP)
    RET
