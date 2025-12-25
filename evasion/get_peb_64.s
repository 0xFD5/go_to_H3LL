// +build amd64

TEXT ·GetPEB(SB), $0-8
    MOVQ 0x60(GS), AX
    MOVQ AX, ret+0(FP)
    RET