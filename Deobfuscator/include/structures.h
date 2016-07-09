#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <string_func.h>

#ifdef _WIN32
	#include <windows.h>
#endif

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <unicorn/unicorn/unicorn.h>
#include <flags.h>

typedef enum InsnType {
	X86_DST_REG_SRC_REG = 0,
	X86_DST_REG_SRC_MEM,
	X86_DST_REG_SRC_IMM,
	X86_DST_MEM_SRC_REG,
	X86_DST_MEM_SRC_IMM,
	X86_DST_REG,
	X86_DST_MEM,
	X86_DST_IMM,
	X86_NO_OP
} InsnType;

typedef enum RegPosition {
	REG_FIRST = 0,
	REG_SECOND,
	REG_THIRD,
	REG_FOURTH
} RegPosition;

typedef struct Instruction {
	cs_insn *insn;					//pointer to the Capstone structure cs_insn
	bool invalid;					//it indicates if the instruction is a fake one (e.g. mov eax, eflags)
	uint64_t fake_mem_addr;			//this field was added as a hackish solution, it contains a fake memory address
	uint64_t fake_mem_addr_2;		//this field was added as a hackish solution, it contains a fake memory address (the second one in case we have PUSH [MEM])
} Instruction;

typedef struct MemoryLocation {
	uint8_t seg;				//the memory segment (CS, DS, SS, ES, FS, GS)
	uint8_t size;				//the memory size: 1, 2, 4, 8 bytes
	uint8_t base;				//specifies the base register
	uint8_t index;				//specifies the index register
	uint32_t scale;				//specifies the scale value
	uint32_t disp;				//specifies the displacement value
	int32_t off;				//specifies the offset
} MemoryLocation;

typedef struct MemoryValue {
	Instruction *insn;
	uint64_t address;
	uint64_t value;
	uint8_t size;
} MemoryValue;

typedef struct Registers {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsp;
	uint64_t rbp;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t eflags;
	uint64_t rip;
} Registers;

typedef struct InsnMatch {
	InsnType type;				//indicates the type of instruction to match
	uint32_t id;				//it is the instruction opcode, refer to x86_insn from Capstone
	uint8_t dst_reg;			//destination register
	uint8_t dst_acc_type;		//destination register access type
	uint8_t src_reg;			//source register
	uint8_t src_acc_type;		//source register access type
	//uint8_t third_reg;		//third register -> unused for now
	//uint8_t fourth_reg;		//fourth register -> unused for now
	uint64_t src_imm;			//source immediate
	MemoryLocation mem;			//memory location structure: base, index, scale, displacement
	uint8_t mem_acc_type;		//memory location access type
	bool ignore_id;				//used to ignore the specific instruction (for example I want to search both MOV and LEA)
	bool specific_match;		//used to know if we need a specific match or a general (only the 'type' is checked)
	bool match_imm_mem;			//used to match a memory value using only the "disp" (for example LEA EAX, [0x777])
	bool wildcard_dst_reg;		//wildcard flag for dst_reg, when set dst_reg is ignored
	bool wildcard_src_reg;		//wildcard flag for src_reg, when set src_reg is ignored
	bool wildcard_mem;			//wildcard flag for mem, when set mem is ignored
	bool wildcard_imm;			//wildcard flag for imm, when set imm is ignored
} InsnMatch;

typedef struct InsnAccess {
	uint8_t access_type;		//determine the access type, using the Capstone ones: CS_AC_READ, CS_AC_WRITE & (CS_AC_READ|CS_AC_WRITE)
	uint8_t op_type;			//determine the type of the operand to check, using the Capstone ones: X86_OP_REG, X86_OP_MEM & X86_OP_IMM
	uint8_t reg;				//the register to trace
	MemoryLocation mem;			//the memory location to trace
	bool same_reg;				//used to know if we want an equality check of the register, or a is_same_register_type is ok
	bool reg_overwrite;			//used to check if the matched register is greater_equal than the searched one
	uint8_t mode;				//used to know if the match is to be done of CS_MODE_32 or CS_MODE_64
} InsnAccess;

typedef union InsnOperand {
	uint8_t reg;				//used to specify the new reg code
	uint64_t imm;				//used to specify the new imm value
	MemoryLocation mem;			//used to specify the new mem values
} InsnOperand;

typedef struct RegVal {
	uint8_t reg;
	uint8_t reg_ref;
	uint64_t val;
	bool invalid;
	bool known;
} RegVal;

typedef struct MemVal {
	uint64_t fake_addr;	//fake address used for memory identification
	uint64_t imm;
	uint8_t reg;
	uint8_t size;
	MemoryLocation mem;
	bool invalid;
	bool known;
} MemVal;