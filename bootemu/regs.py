from typing import Any
from unicorn import Uc  # pyright: ignore[reportPrivateImportUsage]

from unicorn.x86_const import (
    UC_X86_REG_AH,
    UC_X86_REG_AL,
    UC_X86_REG_AX,
    UC_X86_REG_BH,
    UC_X86_REG_BL,
    UC_X86_REG_BX,
    UC_X86_REG_CH,
    UC_X86_REG_CL,
    UC_X86_REG_CX,
    UC_X86_REG_DH,
    UC_X86_REG_DL,
    UC_X86_REG_DX,
    UC_X86_REG_SI,
    UC_X86_REG_DI,
    UC_X86_REG_BP,
    UC_X86_REG_SP,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_ES,
    UC_X86_REG_SS,
    UC_X86_REG_IP,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
    UC_X86_REG_EBP,
    UC_X86_REG_ESP,
    UC_X86_REG_EIP,
)


class UcReg:
    """Descriptor for Unicorn register access."""

    def __init__(self, reg_const: int):
        self.reg_const = reg_const

    def __get__(self, obj: Any, objtype: type | None = None) -> int:
        if obj is None:
            return self  # type: ignore[return-value]
        return obj._uc.reg_read(self.reg_const)

    def __set__(self, obj: Any, value: int) -> None:
        obj._uc.reg_write(self.reg_const, value)


def reg(reg_const: int) -> int:
    return UcReg(reg_const)  # type: ignore[return-value]


"""
"ah": UC_X86_REG_AH,
            "al": UC_X86_REG_AL,
            "ax": UC_X86_REG_AX,
            "bh": UC_X86_REG_BH,
            "bl": UC_X86_REG_BL,
            "bx": UC_X86_REG_BX,
            "ch": UC_X86_REG_CH,
            "cl": UC_X86_REG_CL,
            "cx": UC_X86_REG_CX,
            "dh": UC_X86_REG_DH,
            "dl": UC_X86_REG_DL,
            "dx": UC_X86_REG_DX,
            "si": UC_X86_REG_SI,
            "di": UC_X86_REG_DI,
            "bp": UC_X86_REG_BP,
            "sp": UC_X86_REG_SP,
            "cs": UC_X86_REG_CS,
            "ds": UC_X86_REG_DS,
            "es": UC_X86_REG_ES,
            "ss": UC_X86_REG_SS,
            "ip": UC_X86_REG_IP,
            "flags": UC_X86_REG_EFLAGS,
            """


class X86Regs:
    # 8-bit
    ah: int = reg(UC_X86_REG_AH)
    al: int = reg(UC_X86_REG_AL)
    bh: int = reg(UC_X86_REG_BH)
    bl: int = reg(UC_X86_REG_BL)
    ch: int = reg(UC_X86_REG_CH)
    cl: int = reg(UC_X86_REG_CL)
    dh: int = reg(UC_X86_REG_DH)
    dl: int = reg(UC_X86_REG_DL)

    # 16-bit general
    ax: int = reg(UC_X86_REG_AX)
    bx: int = reg(UC_X86_REG_BX)
    cx: int = reg(UC_X86_REG_CX)
    dx: int = reg(UC_X86_REG_DX)
    si: int = reg(UC_X86_REG_SI)
    di: int = reg(UC_X86_REG_DI)
    bp: int = reg(UC_X86_REG_BP)
    sp: int = reg(UC_X86_REG_SP)
    ip: int = reg(UC_X86_REG_IP)

    # 32-bit general
    eax: int = reg(UC_X86_REG_EAX)
    ebx: int = reg(UC_X86_REG_EBX)
    ecx: int = reg(UC_X86_REG_ECX)
    edx: int = reg(UC_X86_REG_EDX)
    esi: int = reg(UC_X86_REG_ESI)
    edi: int = reg(UC_X86_REG_EDI)
    ebp: int = reg(UC_X86_REG_EBP)
    esp: int = reg(UC_X86_REG_ESP)
    eip: int = reg(UC_X86_REG_EIP)

    # Segment
    cs: int = reg(UC_X86_REG_CS)
    ds: int = reg(UC_X86_REG_DS)
    es: int = reg(UC_X86_REG_ES)
    ss: int = reg(UC_X86_REG_SS)

    # Flags
    flags: int = reg(UC_X86_REG_EFLAGS)

    def __init__(self, uc: Uc) -> None:
        self._uc = uc
