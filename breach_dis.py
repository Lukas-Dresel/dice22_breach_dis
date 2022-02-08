from enum import Enum
import struct
import traceback
from typing import Any, List, Tuple

class Opcode(Enum):
    HALT = 0
    LOAD_REG_IMM = 1
    MOV_REG_REG = 2
    ALU_OP = 3
    STORE64_GLOBAL = 4
    LOAD64_GLOBAL = 5
    LOAD64_PROGRAM = 6
    JMP_ABSOLUTE = 7
    JMP_REG = 8
    JMP_EQ = 9
    STACK_OP = 10
    PRINT_REG = 10
    # NOP = 11
    META_DECODE_ROP_CHAIN = 12
    META_VM_POP = 13
    META_VM_PUSH_IMM = 14
    META_VM_PUSH_REG = 15
    META_VM_SYSCALL = 16
    META_VM_EXECUTE_ROPCHAIN = 17
    META_VM_CALL = 18
    META_VM_RET = 19

class ALU_Opcode(Enum) :
    ADD = 0
    SUB = 1
    MUL = 2
    MOD = 3
    AND = 4
    OR = 5
    XOR = 6
    RSHIFT = 7

class OperandType(Enum):
    IMM64 = 0
    IMM64_PROGRAM_ADDRESS = 1
    REG = 2
    ALU_OP = 3
    REG_GLOBAL_ADDRESS = 4
    REG_PROGRAM_ADDRESS = 5
    REG_SYSCALL_NUM = 6

    STACK_OP = 0x100
    STACK_IMM8 = 0x101
    STACK_REG = 0x102

class StackOpcode(Enum):
    PUSH_REG64 = 0
    PUSH_IMM8 = 1
    ADD = 2
    MULT = 3
    XOR = 4
    IS_ZERO = 5
    AND = 6
    POP_REG64 = 7
    UNKNOWN_MAYBE_INIT = 8

class Register(Enum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    STACKP = 15



def oper_repr(oper_type, oper_val):
    if oper_type == OperandType.ALU_OP:
        return oper_val.name
    elif oper_type == OperandType.IMM64:
        return f'{hex(oper_val)}'
    elif oper_type == OperandType.IMM64_PROGRAM_ADDRESS:
        return f'code[{hex(oper_val)}]'
    elif oper_type == OperandType.REG:
        return oper_val.name
    elif oper_type == OperandType.REG_GLOBAL_ADDRESS:
        return f'ram[{oper_val.name}]'
    elif oper_type == OperandType.REG_PROGRAM_ADDRESS:
        return f'code[{oper_val.name}]'
    elif oper_type == OperandType.REG_SYSCALL_NUM:
        return f'syscall_number[{oper_val.name}]'
    elif oper_type == OperandType.STACK_IMM8:
        return hex(oper_val)
    elif oper_type == OperandType.STACK_REG:
        return oper_val.name
    elif oper_type == OperandType.STACK_OP:
        return oper_val.name
    else:
        assert False, f"what the hell is {oper_type=} {oper_val=}"

#!/usr/bin/env python
class DecodedInstruction:
    opcode : Opcode = None
    operands: List[Tuple[OperandType, Any]] = None
    implicit_operands: List[Tuple[OperandType, Any]] = [None]
    length : int = 0

    def __init__(self) -> None:
        self.implicit_operands = []
        self.operands = []

    def success(self):
        assert (self.opcode is None and self.length == 0) or (self.opcode is not None and self.length != 0)
        return self.opcode is not None

    def is_branch(self):
        return self.opcode in {
            Opcode.META_DECODE_ROP_CHAIN,
            Opcode.JMP_ABSOLUTE,
            Opcode.JMP_EQ,
            Opcode.JMP_REG,
            Opcode.HALT,
        }

    def opcode_name(self):
        return {
            Opcode.LOAD_REG_IMM: "mov",
            Opcode.MOV_REG_REG: "mov",
            Opcode.STORE64_GLOBAL: "store",
            Opcode.LOAD64_GLOBAL: "load",
            Opcode.LOAD64_PROGRAM: "load_code",
            Opcode.ALU_OP: "alu",
            Opcode.JMP_ABSOLUTE: "jmp",
            Opcode.JMP_REG: "jmp",
            Opcode.JMP_EQ: "jeq",
            Opcode.HALT: 'HALT',
            Opcode.PRINT_REG: "print",
            Opcode.STACK_OP: "stack",
            Opcode.META_DECODE_ROP_CHAIN: "DECODE_ROP_CHAIN",
            Opcode.META_VM_POP: "POP",
            Opcode.META_VM_PUSH_IMM: "PUSH_IMM64",
            Opcode.META_VM_PUSH_REG: "PUSH_REG",
            Opcode.META_VM_SYSCALL: "SYSCALL",
            Opcode.META_VM_EXECUTE_ROPCHAIN: "EXEC_ROPCHAIN",
            Opcode.META_VM_CALL: "CALL",
            Opcode.META_VM_RET: "RET",
        }[self.opcode]

    def disasm(self):
        if not self.success():
            return 'INVALID_INSTRUCTION'

        return self.opcode_name().ljust(20, ' ') + ', '.join([oper_repr(_typ, _val) for _typ, _val in self.operands])

    def __str__(self):
        return self.disasm()

def u64(bs):
    if len(bs) < 8:
        raise IndexError
    return struct.unpack("<Q", bs)[0]

def p64(val):
    return struct.pack("<Q", val)


MOV_R0_8 = b'\x01'+p64(8)
SUB_SP_R0 = b'\x13\x0f'
ADD_SP_R0 = b'\x03\x0f'
def try_decode_meta(data, addr, mode_print=False):
    decoded = None
    if addr == 0x2681:
        decoded = DecodedInstruction()
        decoded.length = 0x2745 - 0x2681
        decoded.opcode = Opcode.META_DECODE_ROP_CHAIN
        decoded.operands = [
            (OperandType.REG_GLOBAL_ADDRESS, Register.R4),
            (OperandType.REG_PROGRAM_ADDRESS, Register.R5)
        ]

    elif addr == 0x2353:
        decoded = DecodedInstruction()
        decoded.length = 0x23bd - 0x2353
        decoded.opcode = Opcode.META_VM_SYSCALL
        decoded.operands = [
            (OperandType.REG_SYSCALL_NUM, Register.R8),
            (OperandType.REG, Register.R9),
            (OperandType.REG, Register.R10),
            (OperandType.REG, Register.R11),
            (OperandType.REG, Register.R12),
            (OperandType.REG, Register.R13),
        ]

    elif addr == 0x2504:
        import ipdb; ipdb.set_trace()
        decoded = DecodedInstruction()
        decoded.length = 0x2576 - 0x2504
        decoded.opcode = Opcode.META_VM_EXECUTE_ROPCHAIN
        decoded.operands = [
            (OperandType.REG, Register.R4),
        ]

    exp = MOV_R0_8 + ADD_SP_R0
    if data[0] & 0xf == 5 and data[1] & 0xf == 15 and data[2:2+len(exp)] == exp:
        if data[2 + 9 + 2] == 0x18:
            # this is actually a call
            decoded = DecodedInstruction()
            decoded.length = 2 + 9 + 2 + 1
            decoded.opcode = Opcode.META_VM_RET
            decoded.operands = []
            decoded.implicit_operands = [(OperandType.REG_GLOBAL_ADDRESS, Register.STACKP)]

        else:
            decoded = DecodedInstruction()
            decoded.length = 2 + 9 + 2
            decoded.opcode = Opcode.META_VM_POP
            decoded.operands = [(OperandType.REG, Register(data[1] >> 4))]
            decoded.implicit_operands = [(OperandType.REG_GLOBAL_ADDRESS, Register.STACKP)]

    exp = MOV_R0_8 + SUB_SP_R0 + b"\x01"
    if data[:len(exp)] == exp and data[len(exp)+8:][:2] == b'\x04\x0f':
        maybe_addr = u64(data[len(exp)+8+2+1:][:8])
        if data[len(exp)+8+2] == 0x07:
            # this is actually a call
            decoded = DecodedInstruction()
            decoded.length = len(exp) + 8 + 2 + 9
            decoded.opcode = Opcode.META_VM_CALL
            decoded.operands = [
                (OperandType.IMM64_PROGRAM_ADDRESS, maybe_addr)
            ]
            decoded.implicit_operands = [(OperandType.REG_GLOBAL_ADDRESS, Register.STACKP)]
        else:
            decoded = DecodedInstruction()
            decoded.length = len(exp) + 8 + 2
            decoded.opcode = Opcode.META_VM_PUSH_IMM
            decoded.operands = [
                (OperandType.IMM64, u64(data[len(exp):][:8]))
            ]
            decoded.implicit_operands = [(OperandType.REG_GLOBAL_ADDRESS, Register.STACKP)]

    exp = MOV_R0_8 + SUB_SP_R0 + b'\x04'
    if data[:len(exp)] == exp and data[len(exp)] & 0xf == 0xf:
        reg = Register(data[len(exp)] >> 4)
        decoded = DecodedInstruction()
        decoded.length = len(exp) + 1
        decoded.opcode = Opcode.META_VM_PUSH_REG
        decoded.operands = [
            (OperandType.REG, reg)
        ]
        decoded.implicit_operands = [(OperandType.REG_GLOBAL_ADDRESS, Register.STACKP)]

    return decoded


def decode_basic(data, addr, mode_print=False):
    try:
        decoded = DecodedInstruction()
        op = data[0] & 0xf
        if op == 0:
            decoded.length = 1
            decoded.opcode = Opcode.HALT
            decoded.operands = []
            return decoded
        elif op == 1:
            decoded.opcode = Opcode.LOAD_REG_IMM
            decoded.length = 9
            decoded.operands = [
                (OperandType.REG, Register(data[0] >> 4)),
                (OperandType.IMM64, u64(data[1:9])),
            ]
        elif op == 2:
            decoded.opcode = Opcode.MOV_REG_REG
            decoded.length = 2
            decoded.operands = [
                (OperandType.REG, Register(data[1] & 0xf)),
                (OperandType.REG, Register(data[1] >> 4)),
            ]
        elif op == 3:
            alu_op = data[0] >> 4
            if not (0 <= alu_op < 8):
                return decoded
            decoded.opcode = Opcode.ALU_OP
            decoded.length = 2
            decoded.operands = [
                (OperandType.ALU_OP, ALU_Opcode(alu_op)),
                (OperandType.REG, Register(data[1] & 0xf)),
                (OperandType.REG, Register(data[1] >> 4)),
            ]
        elif op == 4:
            decoded.opcode = Opcode.STORE64_GLOBAL
            decoded.length = 2
            decoded.operands = [
                (OperandType.REG_GLOBAL_ADDRESS, Register(data[1] & 0xf)),
                (OperandType.REG, Register(data[1] >> 4)),
            ]

        elif op == 5:
            decoded.opcode = Opcode.LOAD64_GLOBAL
            decoded.length = 2
            decoded.operands = [
                (OperandType.REG, Register(data[1] >> 4)),
                (OperandType.REG_GLOBAL_ADDRESS, Register(data[1] & 0xf)),
            ]

        elif op == 6:
            decoded.opcode = Opcode.LOAD64_PROGRAM
            decoded.length = 2
            decoded.operands = [
                (OperandType.REG, Register(data[1] >> 4)),
                (OperandType.REG_PROGRAM_ADDRESS, Register(data[1] & 0xf)),
            ]

        elif op == 7:
            decoded.opcode = Opcode.JMP_ABSOLUTE
            decoded.length = 9
            decoded.operands = [
                (OperandType.IMM64_PROGRAM_ADDRESS, u64(data[1:9])),
            ]

        elif op == 8:
            decoded.opcode = Opcode.JMP_REG
            decoded.length = 1
            decoded.operands = [
                (OperandType.REG_PROGRAM_ADDRESS, Register(data[0] >> 4)),
            ]

        elif op == 9:
            decoded.opcode = Opcode.JMP_EQ
            decoded.length = 10
            decoded.operands = [
                (OperandType.REG, Register(data[1] & 0xf)),
                (OperandType.REG, Register(data[1] >> 4)),
                (OperandType.IMM64_PROGRAM_ADDRESS, u64(data[2:10])),
            ]

        elif op == 10:
            decoded.opcode = Opcode.PRINT_REG if mode_print else Opcode.STACK_OP
            decoded.length = 2
            if mode_print:
                decoded.operands = [
                    (OperandType.REG, Register(data[1] & 0xf)),
                ]
            else:
                stack_op = data[0] >> 4
                decoded.operands = [(OperandType.STACK_OP, StackOpcode(stack_op))]

                print(f"Addr: {hex(addr)}, data: {repr(data[:8])}, operands: {decoded.operands}")
                print(f"reg: {hex(data[1])}")
                decoded.operands += {
                    StackOpcode.PUSH_REG64: lambda: [(OperandType.STACK_REG, Register(data[1]))],
                    StackOpcode.PUSH_IMM8:  lambda: [(OperandType.STACK_IMM8, data[1])],
                    StackOpcode.ADD:        lambda: [],
                    StackOpcode.MULT:       lambda: [],
                    StackOpcode.XOR:        lambda: [],
                    StackOpcode.IS_ZERO:    lambda: [],
                    StackOpcode.AND:        lambda: [],
                    StackOpcode.POP_REG64:  lambda: [(OperandType.STACK_REG, Register(data[1]))],
                    StackOpcode.UNKNOWN_MAYBE_INIT: lambda: [],
                }[decoded.operands[0][1]]()

    except IndexError as ex:
        traceback.print_exc()
        decoded = DecodedInstruction()

    return decoded

def decode(data, addr, mode_print=False):
    try:
        res = try_decode_meta(data, addr)
        if res and res.success():
            return res
        return decode_basic(data, addr, mode_print)
    except Exception as ex:
        traceback.print_exc()
        return DecodedInstruction()

