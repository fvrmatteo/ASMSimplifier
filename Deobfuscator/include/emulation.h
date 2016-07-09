//CONSTANT FOLDING - CONSTANT PROPAGATION

//Varibles used for constant folding
List *mem_vals, *reg_vals;
ListEntry *current;
Registers *ctx_curr, *ctx_prev;
bool first;
csh hndl;

//Useful constants
#define INVALIDATE_ALL 0
#define INVALIDATE_PARTIAL 1

/*
	Name: is_imm64_forbidden
	Description: this function will check if 'insn' is forbidden from using 64 bit immediate.
*/
static bool is_imm64_forbidden(Instruction *insn) {
	switch(insn->insn->id) {
		case X86_INS_ADD:
		case X86_INS_PUSH:
			return true;
	}
	return false;
}

/*
	Name: is_blacklisted
	Description: this function will tell if an instruction can be updated.
*/
static bool is_blacklisted(Instruction *insn) {
	switch(insn->insn->id) {
		case X86_INS_BTS:
		case X86_INS_CMOVO:
		case X86_INS_PUSH:	//THIS CAN BE ENABLED AGAIN
		case X86_INS_MOVSX:
		case X86_INS_XCHG:
		case X86_INS_MUL:
			return true;
	}
	return false;
}

/*
	Name: clean_reg
	Description: this function will clean (zero) part of a register: AL, AH, AX, EAX, RAX.
*/
static uint64_t clean_reg(uint64_t val, uint8_t reg_code) {
	switch(reg_code) {
		case 0x10: return (val & 0xFFFFFFFFFFFFFF00);
		case 0x20: return (val & 0xFFFFFFFFFFFF00FF);
		case 0x30: return (val & 0xFFFFFFFFFFFF0000);
		case 0x40: return (val & 0xFFFFFFFF00000000);
		case 0x50: return (val & 0x0);
	}
	return val;
}

/*
	Name: merge_regs
	Description: this function will merge two registers values, where .
*/
static void merge_regs(uint8_t reg1, uint64_t val1, uint8_t reg2, uint64_t val2, uint8_t *out_reg, uint64_t *out_val) {
	uint8_t r1_code = reg_code(reg1), r2_code = reg_code(reg2);
	if(r1_code >= 0x30 && r1_code >= r2_code) {
		//we know a value for 'reg1' equal to or bigger than AX
		*out_reg = reg1;
		*out_val = clean_reg(val1, r2_code) | val2;
	} else if(r1_code < r2_code && r2_code >= 0x30) {
		//we know reg2 is bigger than r1 and overwrites it
		*out_reg = reg2;
		*out_val = val2;
	} else if(r1_code == 0x20 && r2_code == 0x10) {
		//we know the registers are AH-AL
		*out_reg = register_from_code(0x30 | reg_type(reg1));
		*out_val = (val1 << 8) | val2;
	} else if(r1_code == 0x10 && r2_code == 0x20) {
		//we know the registers are AL-AH
		*out_reg = register_from_code(0x30 | reg_type(reg1));
		*out_val = val1 | (val2 << 8);
	} else if(r1_code == r2_code) {
		//we know the registers are equals
		*out_reg = reg1;
		if(r1_code == 0x20) val2 <<= 8;
		*out_val = val2;
	}
}

/*
	Name: print_reg_vals
	Description: this function will print the registers contained in 'reg_vals'.
*/
static void print_reg_vals() {
	printf("\nRegister values:\n");
	ListEntry *current = reg_vals->first;
	RegVal *curr_reg;
	while(current) {
		//extract RegVal
		curr_reg = (RegVal *)current->content;
		if(!curr_reg->invalid) {
			//print information
			printf("{ .reg = %s, .imm = 0x%lx, .reg_ref = %s, .known = %d, .invalid = %d }\n",
			(char *)cs_reg_name(hndl, curr_reg->reg), curr_reg->val, (char *)cs_reg_name(hndl, curr_reg->reg_ref), curr_reg->known, curr_reg->invalid);
		}
		//go to the next RegVal
		current = current->next;
	}
}

/*
	Name: print_mem_vals
	Description: this function will print the memory locations contained in 'mem_vals'.
*/
static void print_mem_vals() {
	printf("\nMemory values:\n");
	ListEntry *current = mem_vals->first;
	MemVal *curr_mem;
	while(current) {
		//extract MemVal
		curr_mem = (MemVal *)current->content;
		if(!curr_mem->invalid) {
			//print information
			printf("{ .addr = 0x%lx, .size = %d, .imm = 0x%lx, .reg = %s, .known = %d, .invalid = %d }\n",
			curr_mem->fake_addr, curr_mem->size, curr_mem->imm, cs_reg_name(hndl, curr_mem->reg), curr_mem->known, curr_mem->invalid);
		}
		//go to the next MemVal
		current = current->next;
	}
}

/*
	Name: get_val
	Description: this function will read the register value from the current Unicorn emulation context.
*/
static uint64_t get_val(uint8_t reg, Registers *ctx) {
	switch(reg) {
		case X86_REG_RAX: return ctx->rax;
		case X86_REG_EAX: return (ctx->rax & 0xFFFFFFFF);
		case X86_REG_AX: return (ctx->rax & 0xFFFF);
		case X86_REG_AH: return ((ctx->rax & 0xFFFF) >> 8);
		case X86_REG_AL: return (ctx->rax & 0xFF);
		
		case X86_REG_RBX: return ctx->rbx;
		case X86_REG_EBX: return (ctx->rbx & 0xFFFFFFFF);
		case X86_REG_BX: return (ctx->rbx & 0xFFFF);
		case X86_REG_BH: return ((ctx->rbx & 0xFFFF) >> 8);
		case X86_REG_BL: return (ctx->rbx & 0xFF);
		
		case X86_REG_RCX: return ctx->rcx;
		case X86_REG_ECX: return (ctx->rcx & 0xFFFFFFFF);
		case X86_REG_CX: return (ctx->rcx & 0xFFFF);
		case X86_REG_CH: return ((ctx->rcx & 0xFFFF) >> 8);
		case X86_REG_CL: return (ctx->rcx & 0xFF);
		
		case X86_REG_RDX: return ctx->rdx;
		case X86_REG_EDX: return (ctx->rdx & 0xFFFFFFFF);
		case X86_REG_DX: return (ctx->rdx & 0xFFFF);
		case X86_REG_DH: return ((ctx->rdx & 0xFFFF) >> 8);
		case X86_REG_DL: return (ctx->rdx & 0xFF);
		
		case X86_REG_RSP: return ctx->rsp;
		case X86_REG_ESP: return (ctx->rsp & 0xFFFFFFFF);
		case X86_REG_SP: return (ctx->rsp & 0xFFFF);
		case X86_REG_SPL: return (ctx->rsp & 0xFF);
		
		case X86_REG_RBP: return ctx->rbp;
		case X86_REG_EBP: return (ctx->rbp & 0xFFFFFFFF);
		case X86_REG_BP: return (ctx->rbp & 0xFFFF);
		case X86_REG_BPL: return (ctx->rbp & 0xFF);
		
		case X86_REG_RSI: return ctx->rsi;
		case X86_REG_ESI: return (ctx->rsi & 0xFFFFFFFF);
		case X86_REG_SI: return (ctx->rsi & 0xFFFF);
		case X86_REG_SIL: return (ctx->rsi & 0xFF);
		
		case X86_REG_RDI: return ctx->rdi;
		case X86_REG_EDI: return (ctx->rdi & 0xFFFFFFFF);
		case X86_REG_DI: return (ctx->rdi & 0xFFFF);
		case X86_REG_DIL: return (ctx->rdi & 0xFF);
		
		case X86_REG_R8: return ctx->r8;
		case X86_REG_R8D: return (ctx->r8 & 0xFFFFFFFF);
		case X86_REG_R8W: return (ctx->r8 & 0xFFFF);
		case X86_REG_R8B: return (ctx->r8 & 0xFF);
		
		case X86_REG_R9: return ctx->r9;
		case X86_REG_R9D: return (ctx->r9 & 0xFFFFFFFF);
		case X86_REG_R9W: return (ctx->r9 & 0xFFFF);
		case X86_REG_R9B: return (ctx->r9 & 0xFF);
		
		case X86_REG_R10: return ctx->r10;
		case X86_REG_R10D: return (ctx->r10 & 0xFFFFFFFF);
		case X86_REG_R10W: return (ctx->r10 & 0xFFFF);
		case X86_REG_R10B: return (ctx->r10 & 0xFF);
		
		case X86_REG_R11: return ctx->r11;
		case X86_REG_R11D: return (ctx->r11 & 0xFFFFFFFF);
		case X86_REG_R11W: return (ctx->r11 & 0xFFFF);
		case X86_REG_R11B: return (ctx->r11 & 0xFF);
		
		case X86_REG_R12: return ctx->r12;
		case X86_REG_R12D: return (ctx->r12 & 0xFFFFFFFF);
		case X86_REG_R12W: return (ctx->r12 & 0xFFFF);
		case X86_REG_R12B: return (ctx->r12 & 0xFF);
		
		case X86_REG_R13: return ctx->r13;
		case X86_REG_R13D: return (ctx->r13 & 0xFFFFFFFF);
		case X86_REG_R13W: return (ctx->r13 & 0xFFFF);
		case X86_REG_R13B: return (ctx->r13 & 0xFF);
		
		case X86_REG_R14: return ctx->r14;
		case X86_REG_R14D: return (ctx->r14 & 0xFFFFFFFF);
		case X86_REG_R14W: return (ctx->r14 & 0xFFFF);
		case X86_REG_R14B: return (ctx->r14 & 0xFF);
		
		case X86_REG_R15: return ctx->r15;
		case X86_REG_R15D: return (ctx->r15 & 0xFFFFFFFF);
		case X86_REG_R15W: return (ctx->r15 & 0xFFFF);
		case X86_REG_R15B: return (ctx->r15 & 0xFF);
	}
	return 0;
}

/*
	Name: memory_overlap
	Description: this function will check for a memory overlap.
*/
static bool memory_overlap(uint64_t addr1, uint8_t sz1, uint64_t addr2, uint8_t sz2) {
	uint64_t l1 = addr1, h1 = addr1 + sz1, l2 = addr2, h2 = addr2 + sz2;
	return ((l2 >= l1 && l2 < h1) || (l1 >= l2 && l1 < h2));
}

/*
	Name: get_mem
	Description: this function will extract 'reg' or 'imm' from a known memory location.
*/
static bool get_mem_val(uc_engine *uc, MemVal *mem_val) {
	//clean mem_val
	mem_val->imm = 0;
	mem_val->known = false;
	mem_val->invalid = false;
	mem_val->reg = X86_REG_INVALID;
	//search the memory list for a possible known value
	ListEntry *current = mem_vals->first;
	MemVal *curr_mem;
	while(current) {
		//extract MemVal
		curr_mem = (MemVal *)current->content;
		//check if this is the memory location we are looking for
		if(!curr_mem->invalid && memory_overlap(curr_mem->fake_addr, curr_mem->size, mem_val->fake_addr, mem_val->size)) {
			if(curr_mem->known) {
				mem_val->known = true;
				//mem_val->imm = res_imm(curr_mem->imm, mem_val->size);
				uc_mem_read(uc, mem_val->fake_addr, &mem_val->imm, mem_val->size);
				printf("get_mem_val(0x%lx:%d) = 0x%lx\n", curr_mem->fake_addr, mem_val->size, mem_val->imm);
				return true;
			} else if(is_valid(curr_mem->reg) && curr_mem->fake_addr == mem_val->fake_addr) {
				mem_val->known = false;
				mem_val->reg = res_reg(curr_mem->reg, mem_val->size);
				printf("get_mem_val(0x%lx:%d) = %s\n", curr_mem->fake_addr, mem_val->size, cs_reg_name(hndl, mem_val->reg));
				return true;
			}
		}
		//check the next memory location
		current = current->next;
	}
	return false;
}

/*
	Name: get_reg
	Description: this function will extract 'reg' or 'imm' from a known register.
*/
static bool get_reg_val(RegVal *reg_val) {
	//clean RegVal
	reg_val->reg_ref = X86_REG_INVALID;
	reg_val->invalid = false;
	reg_val->known = false;
	reg_val->val = 0;
	//search the register list for a possible known value
	ListEntry *current = reg_vals->first;
	RegVal *curr_reg;
	while(current) {
		//extract RegVal
		curr_reg = (RegVal *)current->content;
		//check if this is the register we are looking for
		//if(!curr_reg->invalid && is_same_register_type(reg_val->reg, curr_reg->reg)) {
		if(!curr_reg->invalid && is_eq_or_subregister(reg_val->reg, curr_reg->reg)) {
			if(curr_reg->known) {
				reg_val->known = true;
				//reg_val->val = resize_immediate(curr_reg->val, reg_val->reg);
				reg_val->val = get_val(reg_val->reg, ctx_curr);
				//printf("get_reg_val(%s) = 0x%lx\n", cs_reg_name(hndl, reg_val->reg), reg_val->val);
				return true;
			} else if(is_valid(curr_reg->reg_ref)) {
				reg_val->known = false;
				reg_val->reg_ref = resize_reg(curr_reg->reg_ref, reg_val->reg);
				//printf("get_reg_val(%s) = %s\n", cs_reg_name(hndl, reg_val->reg), cs_reg_name(hndl, reg_val->reg_ref));
				return true;
			}
		}
		//check the next register
		current = current->next;
	}
	return false;
}

/*
	Name: save_mem
	Description: this function will add 'mem_val' to the list of known memory locations; if the
	memory location is known, update it.
*/
static void save_mem(uc_engine *uc, MemVal *mem_val) {
	ListEntry *current = mem_vals->first;
	MemVal *curr_mem;
	while(current) {
		//extract MemVal
		curr_mem = (MemVal *)current->content;
		if(curr_mem->fake_addr == mem_val->fake_addr) {
			if(curr_mem->known && curr_mem->size > mem_val->size) {
				//extract and update the immediate value
				uc_mem_read(uc, curr_mem->fake_addr, &mem_val->imm, curr_mem->size);
				mem_val->size = curr_mem->size;
			} else if(!curr_mem->invalid && !curr_mem->known && is_eq_or_subregister(mem_val->reg, curr_mem->reg)) {
				//we need to update the referenced reg
				mem_val->reg = curr_mem->reg;
				mem_val->size = curr_mem->size;
			}
			memcpy(curr_mem, mem_val, sizeof(MemVal));
			return;
		}
		//go to the next memory location
		current = current->next;
	}
	//the memory location was not present, add it to the list
	MemVal *mem = calloc(1, sizeof(MemVal));
	memcpy(mem, mem_val, sizeof(MemVal));
	ListPush(mem_vals, ListEntryCreate(mem));
}

/*
	Name: save_reg
	Description: this function will add 'reg_val' to the list of known registers; if the register
	is known, update it.
*/
static void save_reg(RegVal *reg_val) {
	ListEntry *current = reg_vals->first;
	RegVal *curr_reg;
	while(current) {
		//extract RegVal
		curr_reg = (RegVal *)current->content;
		if(is_same_register_type(curr_reg->reg, reg_val->reg)) {
			//we need to merge 2 registers vals if we know both immediate values
			if(reg_val->known && curr_reg->known) {
				merge_regs(curr_reg->reg, curr_reg->val, reg_val->reg, reg_val->val, &reg_val->reg, &reg_val->val);
			}
			//we need to merge 2 registers reg_refs if we know both registers are not invalid and not known
			if(!reg_val->known && !reg_val->invalid && !curr_reg->known && !curr_reg->invalid) {
				
			}
			//update the value
			memcpy(curr_reg, reg_val, sizeof(RegVal));
			return;
		}
		//go to the next register
		current = current->next;
	}
	//the register was not present, add it to the list
	RegVal *reg = calloc(1, sizeof(RegVal));
	memcpy(reg, reg_val, sizeof(RegVal));
	ListPush(reg_vals, ListEntryCreate(reg));
}

/*
	Name: invalidate_mem
	Description: this function will invalidate the memory location touched by 'insn'.
*/
static void invalidate_mem(Instruction *insn, uint8_t type) {
	ListEntry *current;
	MemVal *curr_mem;
	//invalidate each memory locations who contains an invalid register
	cs_x86 *x86 = &(insn->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	//invalidate explicit registers
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_REG && (op->access == CS_AC_WRITE || op->access == (CS_AC_READ|CS_AC_WRITE))) {
			current = mem_vals->first;
			while(current) {
				//extract MemVal
				curr_mem = (MemVal *)current->content;
				//check if this memory location contains a reference to a modified register
				if(is_valid(curr_mem->reg) && is_same_register_type(curr_mem->reg, op->reg)) {
					curr_mem->reg = X86_REG_INVALID;
					curr_mem->invalid = true;
					curr_mem->known = false;
				}
				//go to the next MemVal
				current = current->next;
			}
		}
	}
	//invalidate implicit registers
	size_t regs_write_count = insn->insn->detail->regs_write_count;
	uint8_t reg = X86_REG_INVALID;
	for(size_t i = 0; i < regs_write_count; i++) {
		reg = insn->insn->detail->regs_write[i];
		current = mem_vals->first;
		while(current) {
			//extract MemVal
			curr_mem = (MemVal *)current->content;
			//check if this memory location contains a reference to a modified register
			if(is_valid(curr_mem->reg) && is_same_register_type(curr_mem->reg, reg)) {
				curr_mem->reg = X86_REG_INVALID;
				curr_mem->invalid = true;
				curr_mem->known = false;
			}
			//go to the next MemVal
			current = current->next;
		}
	}
	//invalidate each memory locations which overlaps with the memory locations modified by 'insn'
	MemoryLocation mem = { 0 };
	if(insn->fake_mem_addr && (get_dst_mem(insn, &mem, CS_AC_WRITE) || get_dst_mem(insn, &mem, CS_AC_WRITE|CS_AC_READ))) {
		current = mem_vals->first;
		while(current) {
			//extract MemVal
			curr_mem = (MemVal *)current->content;
			//check for memory overlap
			if(memory_overlap(curr_mem->fake_addr, curr_mem->size, insn->fake_mem_addr, mem.size)) {
				//ignore perfect match if type == INVALIDATE_PARTIAL and the memory is contained
				if(type == INVALIDATE_PARTIAL) {
					uint64_t l = curr_mem->fake_addr, h = curr_mem->fake_addr + curr_mem->size;
					uint64_t l_in = insn->fake_mem_addr, h_in = insn->fake_mem_addr + mem.size;
					if(l_in >= l && h_in <= h) {
						current = current->next;
						continue;
					}
				}
				curr_mem->reg = X86_REG_INVALID;
				curr_mem->invalid = true;
				curr_mem->known = false;
				curr_mem->imm = 0;
			}
			//go to the next MemVal
			current = current->next;
		}
	}
	//this one is reserved to PUSH instruction
	if(insn->fake_mem_addr_2 && cmp_id(insn->insn->id, X86_INS_PUSH)) {
		current = mem_vals->first;
		while(current) {
			//extract MemVal
			curr_mem = (MemVal *)current->content;
			//check for memory overlap
			if(memory_overlap(curr_mem->fake_addr, curr_mem->size, insn->fake_mem_addr_2, insn->insn->detail->x86.operands[0].size)) {
				//ignore perfect match if type == INVALIDATE_PARTIAL
				if(type == INVALIDATE_PARTIAL && curr_mem->fake_addr == insn->fake_mem_addr_2 && curr_mem->size == insn->insn->detail->x86.operands[0].size) {
					current = current->next;
					continue;
				}
				curr_mem->reg = X86_REG_INVALID;
				curr_mem->invalid = true;
				curr_mem->known = false;
				curr_mem->imm = 0;
			}
			//go to the next MemVal
			current = current->next;
		}
	}
}

/*
	Name: invalidate_reg
	Description: this function will invalidate the registers touched by 'insn'.
*/
static void invalidate_reg(Instruction *insn, uint8_t type) {
	ListEntry *current;
	RegVal *curr_reg;
	//invalidate each register modified by this instruction
	cs_x86 *x86 = &(insn->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	//invalidate explicit registers
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_REG && (op->access == CS_AC_WRITE || op->access == (CS_AC_READ|CS_AC_WRITE))) {
			current = reg_vals->first;
			while(current) {
				//extract RegVal
				curr_reg = (RegVal *)current->content;
				//check if this registers contains a link to another register
				if((type == INVALIDATE_ALL && is_same_register_type(curr_reg->reg, op->reg)) || (is_valid(curr_reg->reg_ref) && is_same_register_type(curr_reg->reg_ref, op->reg))) {
					curr_reg->reg_ref = X86_REG_INVALID;
					curr_reg->invalid = true;
					curr_reg->known = false;
					curr_reg->val = 0;
				}
				//go to the next RegVal
				current = current->next;
			}
		}
	}
	//invalidate implicit registers
	size_t regs_write_count = insn->insn->detail->regs_write_count;
	uint8_t reg = X86_REG_INVALID;
	for(size_t i = 0; i < regs_write_count; i++) {
		reg = insn->insn->detail->regs_write[i];
		current = reg_vals->first;
		while(current) {
			//extract RegVal
			curr_reg = (RegVal *)current->content;
			//check if this registers contains a link to another register
			if((type == INVALIDATE_ALL && is_same_register_type(curr_reg->reg, reg)) || (is_valid(curr_reg->reg_ref) && is_same_register_type(curr_reg->reg_ref, reg))) {
				curr_reg->reg_ref = X86_REG_INVALID;
				curr_reg->invalid = true;
				curr_reg->known = false;
				curr_reg->val = 0;
			}
			//go to the next RegVal
			current = current->next;
		}
	}
}

/*
	Name: update_mem_ref
	Description: this function will update the memory location touched by 'insn'.
*/
static void update_mem_ref(uc_engine *uc, Instruction *insn) {
	MemoryLocation mem = { 0 }; uint8_t reg;
	//update reg reference for standard memory
	if(get_dst_mem(insn, &mem, CS_AC_WRITE) && get_src_reg(insn, &reg, NULL)) {
		MemVal mem_val = { .fake_addr = insn->fake_mem_addr, .size = mem.size, .imm = 0, .reg = reg, .invalid = false, .known = false };
		save_mem(uc, &mem_val);
	}
	//update reg reference for PUSH instruction
	uint8_t size;
	if(cmp_id(insn->insn->id, X86_INS_PUSH) && insn->fake_mem_addr_2 && get_src_reg(insn, &reg, &size)) {
		MemVal mem_val = { .fake_addr = insn->fake_mem_addr_2, .size = size, .imm = 0, .reg = reg, .invalid = false, .known = false };
		save_mem(uc, &mem_val);
	}
	//update reg reference for POP instruction
	MemVal mem_val = { .fake_addr = insn->fake_mem_addr_2, .size = insn->insn->detail->x86.operands[0].size, .known = false };
	if(cmp_id(insn->insn->id, X86_INS_POP) && insn->fake_mem_addr_2 && get_mem_val(uc, &mem_val)) {
		mem_val.fake_addr = insn->fake_mem_addr;
		save_mem(uc, &mem_val);
	}
}

/*
	Name: update_reg_ref
	Description: this function will update the registers touched by 'insn'.
*/
static void update_reg_ref(Instruction *insn) {
	uint8_t dst_reg, src_reg;
	if(!cmp_id(insn->insn->id, X86_INS_PUSH) && get_dst_reg(insn, &dst_reg, NULL, CS_AC_WRITE) && get_src_reg(insn, &src_reg, NULL)) {
		RegVal reg_val = { .reg = dst_reg, .val = 0, .reg_ref = src_reg, .invalid = false, .known = false };
		save_reg(&reg_val);
	}
}

/*
	Name: update_mem
	Description: this function will update the memory location touched by 'insn'.
*/
static void update_mem(uc_engine *uc, Instruction *insn) {
	MemVal mem = { .reg = X86_REG_INVALID, .invalid = false, .known = true };
	uint8_t size;
	if(insn->fake_mem_addr) {
		get_mem_size(insn, &size);
		mem.fake_addr = insn->fake_mem_addr;
		mem.size = size;
		uc_mem_read(uc, mem.fake_addr, &mem.imm, size);
		save_mem(uc, &mem);
	}
	if(insn->fake_mem_addr_2) {
		mem.fake_addr = insn->fake_mem_addr_2;
		mem.size = insn->insn->detail->x86.operands[0].size;
		uc_mem_read(uc, mem.fake_addr, &mem.imm, insn->insn->detail->x86.operands[0].size);
		save_mem(uc, &mem);
	}
}

/*
	Name: update_reg
	Description: this function will update the registers touched by 'insn'.
*/
static void update_reg(Instruction *insn) {
	cs_x86 *x86 = &(insn->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	RegVal reg = { .reg_ref = X86_REG_INVALID, .invalid = false, .known = true };
	//update explicit registers
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_REG && (op->access == CS_AC_WRITE || op->access == (CS_AC_READ|CS_AC_WRITE))) {
			reg.val = get_val(op->reg, ctx_curr);
			reg.reg = op->reg;
			save_reg(&reg);
		}
	}
	//update implicit registers
	size_t regs_write_count = insn->insn->detail->regs_write_count;
	for(size_t i = 0; i < regs_write_count; i++) {
		reg.reg = insn->insn->detail->regs_write[i];
		if(reg.reg == X86_REG_EFLAGS || is_same_register_type(reg.reg, X86_REG_RSP)) continue;
		reg.val = get_val(reg.reg, ctx_curr);
		save_reg(&reg);
	}
}

/*
	Name: fake_mem_addr
	Description: this function will calculate the fake memory address for this instruction.
*/
static uint64_t fake_mem_addr(uc_engine *uc, uint8_t base, uint8_t index, uint32_t scale, int32_t disp) {
	uint64_t base_val = get_val(base, ctx_prev);
	uint64_t index_val = get_val(index, ctx_prev);
	uint64_t addr = (base_val + index_val * scale + disp);
	printf("Calculated fake addr: 0x%lx\n", addr);
	return addr;
}

/*
	Name: dump_reg_context
	Description: this function will dump the current register context.
*/
static void dump_reg_context(uc_engine *uc, Registers *regs) {
	//printf("[i] Dumping register context\n");
	switch(MODE) {
		case CS_MODE_32:
			uc_reg_read(uc, UC_X86_REG_EAX, &(regs->rax));
			uc_reg_read(uc, UC_X86_REG_EBX, &(regs->rbx));
			uc_reg_read(uc, UC_X86_REG_ECX, &(regs->rcx));
			uc_reg_read(uc, UC_X86_REG_EDX, &(regs->rdx));
			uc_reg_read(uc, UC_X86_REG_ESP, &(regs->rsp));
			uc_reg_read(uc, UC_X86_REG_EBP, &(regs->rbp));
			uc_reg_read(uc, UC_X86_REG_ESI, &(regs->rsi));
			uc_reg_read(uc, UC_X86_REG_EDI, &(regs->rdi));
			uc_reg_read(uc, UC_X86_REG_EFLAGS, &(regs->eflags));
			break;
		case CS_MODE_64:
			uc_reg_read(uc, UC_X86_REG_RAX, &(regs->rax));
			uc_reg_read(uc, UC_X86_REG_RBX, &(regs->rbx));
			uc_reg_read(uc, UC_X86_REG_RCX, &(regs->rcx));
			uc_reg_read(uc, UC_X86_REG_RDX, &(regs->rdx));
			uc_reg_read(uc, UC_X86_REG_RSP, &(regs->rsp));
			uc_reg_read(uc, UC_X86_REG_RBP, &(regs->rbp));
			uc_reg_read(uc, UC_X86_REG_RSI, &(regs->rsi));
			uc_reg_read(uc, UC_X86_REG_RDI, &(regs->rdi));
			uc_reg_read(uc, UC_X86_REG_R8, &(regs->r8));
			uc_reg_read(uc, UC_X86_REG_R9, &(regs->r9));
			uc_reg_read(uc, UC_X86_REG_R10, &(regs->r10));
			uc_reg_read(uc, UC_X86_REG_R11, &(regs->r11));
			uc_reg_read(uc, UC_X86_REG_R12, &(regs->r12));
			uc_reg_read(uc, UC_X86_REG_R13, &(regs->r13));
			uc_reg_read(uc, UC_X86_REG_R14, &(regs->r14));
			uc_reg_read(uc, UC_X86_REG_R15, &(regs->r15));
			uc_reg_read(uc, UC_X86_REG_EFLAGS, &(regs->eflags));
			break;
	}
}

/*
	Name: is_context_known
	Description: this function will tell if the context to emulate the instruction is known.
*/
static bool is_valid_context(uc_engine *uc, Instruction *insn) {
	cs_x86 *x86 = &(insn->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	RegVal reg = { 0 };
	MemVal mem = { 0 };
	//check explicit registers and memory locations
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->access == CS_AC_READ || op->access == (CS_AC_READ|CS_AC_WRITE)) {
			switch(op->type) {
				case X86_OP_REG:
					reg.reg = op->reg;
					reg.known = false;
					if(!(get_reg_val(&reg) && reg.known)) {
						return false;
					}
					break;
				case X86_OP_MEM:
					mem.fake_addr = insn->fake_mem_addr;
					mem.size = op->size;
					mem.known = false;
					if(!(get_mem_val(uc, &mem) && mem.known)) {
						return false;
					}
					break;
				default: break;
			}
		}
	}
	//check implicit registers (only read)
	size_t regs_read_count = insn->insn->detail->regs_read_count;
	for(size_t i = 0; i < regs_read_count; i++) {
		reg.reg = insn->insn->detail->regs_read[i];
		reg.known = false;
		if(reg.reg == X86_REG_EFLAGS || is_same_register_type(reg.reg, X86_REG_RSP)) continue;
		if(!(get_reg_val(&reg) && reg.known)) {
			return false;
		}
	}
	//check implicit memory locations (POP)
	mem.fake_addr = insn->fake_mem_addr_2;
	mem.size = insn->insn->detail->x86.operands[0].size;
	mem.known = false;
	if(cmp_id(insn->insn->id, X86_INS_POP) && insn->fake_mem_addr_2 && !(get_mem_val(uc, &mem) && mem.known)) return false;
	return true;
}

/*
	Name: update_op_str
	Description: this function will update the 'op_str' of 'insn' using the current known values.
*/
static void update_op_str(uc_engine *uc, Instruction *insn) {
	//check if the instruction is on the blacklist
	if(is_blacklisted(insn)) return;
	//useful x86 variables
	cs_x86 *x86 = &(insn->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	//useful variables
	RegVal reg;
	MemVal mem;
	bool updated = false;
	//extract op_str
	char new_val[40] = { 0 };
	char *op_str = calloc(160, sizeof(char));
	memcpy(op_str, insn->insn->op_str, strlen(insn->insn->op_str));
	//extract always the first register (if present)
	uint8_t first_reg = get_reg_at(insn, REG_FIRST, NULL);
	//check and update explicit memory locations & registers
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->access == CS_AC_READ || op->access == (CS_AC_READ|CS_AC_WRITE)) {
			//ignore the first operand if it is CS_AC_READ|CS_AC_WRITE
			if(i == 0 && op->access == (CS_AC_READ|CS_AC_WRITE)) {
				continue;
			}
			//update op_str
			switch(op->type) {
				default: break;
				case X86_OP_REG:
					//extract 'new_val'
					reg.reg = op->reg;
					if(get_reg_val(&reg)) {
						//determine if we extracted a 'ref_reg' or a 'val'
						if(reg.known) {
							//check if it is usable on x64 with the current instruction
							if((reg.val & 0xFFFFFFFF00000000) && is_imm64_forbidden(insn)) {
								continue;
							}
							//we found an immediate 'val'
							sprintf(new_val, "0x%lx", reg.val);
						} else {
							//we found a 'reg_ref'
							sprintf(new_val, "%s", cs_reg_name(hndl, reg.reg_ref));
						}
					} else {
						//the value is not present, skip it
						continue;
					}
					//determine if we need to skip the first register
					uint8_t counter = (is_same_register_type(op->reg, first_reg) && i > 0) ? 0 : -1;
					//replace the register with a new value
					op_str = str_replace(op_str, (char *)cs_reg_name(hndl, op->reg), new_val, counter);
					//mark as updated
					updated = true;
					break;
				case X86_OP_MEM:
					//extract 'new_val'
					mem.fake_addr = insn->fake_mem_addr;
					mem.size = op->size;
					if(get_mem_val(uc, &mem)) {
						//determine if we extracted a 'reg' or an 'imm'
						if(mem.known) {
							//check if it is usable on x64 with the current instruction
							if((mem.imm & 0xFFFFFFFF00000000) && is_imm64_forbidden(insn)) {
								continue;
							}
							//we found an immediate 'imm'
							sprintf(new_val, "0x%lx", mem.imm);
						} else {
							//we found a 'reg'
							sprintf(new_val, "%s", cs_reg_name(hndl, mem.reg));
							//remove 'dword ptr' from op_str
							char mem_indicator[20];
							sprintf(mem_indicator, "%s ptr", get_mem_indicator(mem.size));
							op_str = str_replace(op_str, mem_indicator, "", -1);
						}
					} else {
						//the value is not present, skip it
						continue;
					}
					//generate memory string
					char memory_string[60] = { 0 };
					sprintf(memory_string, "[%s]", fix_mem_op_str(hndl, op->mem.base, op->mem.index, op->mem.scale, op->mem.disp));
					//replace the memory location with a new value
					op_str = str_replace(op_str, memory_string, new_val, -1);
					//mark as updated
					updated = true;
					break;
			}
		}
	}
	//assemble new instruction
	if(updated) {
		//save old addresses
		uint64_t fma = insn->fake_mem_addr, fma2 = insn->fake_mem_addr_2;
		//assembled and update instruction
		Instruction *new_insn = assemble_insn(insn->insn->mnemonic, op_str, insn->insn->address, MODE);
		//update addresses
		new_insn->fake_mem_addr = fma;
		new_insn->fake_mem_addr_2 = fma2;
		printf("ASSEMBLED: %s %s\n", new_insn->insn->mnemonic, new_insn->insn->op_str);
		//this is a stupid fix TO BE REMOVED when Keystone is fixed
		if(cmp_id(insn->insn->id, X86_INS_PUSH) && insn->insn->detail->x86.operands[0].size == 2) {
			if(new_insn->insn->bytes[0] != 0x66) {
				printf("\nBroken bytes: ");
				for(size_t i = 0; i < new_insn->insn->size; i++) {
					printf("0x%02X ", new_insn->insn->bytes[i]);
				}
				printf("\n");
				for(size_t i = new_insn->insn->size - 1 ; i > 0; i--) {
					new_insn->insn->bytes[i] = new_insn->insn->bytes[i - 1];
				}
				new_insn->insn->bytes[0] = 0x66;
				new_insn->insn->size--;
				printf("\nFixed bytes: ");
				for(size_t i = 0; i < new_insn->insn->size; i++) {
					printf("0x%02X ", new_insn->insn->bytes[i]);
				}
				printf("\n");
			}
		}
		ListChangeEntry(current, new_insn);
	}
	free(op_str);
}

/*
	Name: hook_code
	Description: this function will apply constant folding/propagation to the Assembly listing.
*/
static void hook_code(uc_engine *uc, uint64_t address, int32_t in_size, void *user_data) {
	//if this is the first instruction, ignore it
	if(first) {
		//dump previous register context
		dump_reg_context(uc, ctx_prev);
		//disable first instruction indicator
		first = false;
		return;
	}
	//dump current register context
	dump_reg_context(uc, ctx_curr);
	//this function could be used to trace & modify operation while emulating code
	Instruction *insn = (Instruction *)current->content;
	print_insn("Tracing	: ", insn);
	//if it is a NOP instruction, ignore it
	if(!is_nop(insn, MODE)) {
		//generate fake memory addresses (standard)
		uint8_t base = (MODE == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
		MemoryLocation mem = { 0 };
		if(get_mem(insn, &mem) && !cmp_id(insn->insn->id, X86_INS_PUSH) && !cmp_id(insn->insn->id, X86_INS_POP)) {
			insn->fake_mem_addr = fake_mem_addr(uc, mem.base, mem.index, mem.scale, mem.disp);
		}
		//generate fake memory addresses (PUSH-POP)
		if(cmp_id(insn->insn->id, X86_INS_PUSH)) {
			uint8_t size = insn->insn->detail->x86.operands[0].size;
			if(get_mem(insn, &mem)) insn->fake_mem_addr = fake_mem_addr(uc, mem.base, mem.index, mem.scale, mem.disp);
			insn->fake_mem_addr_2 = fake_mem_addr(uc, base, X86_REG_INVALID, 1, -size);
		} else if(cmp_id(insn->insn->id, X86_INS_POP)) {
			if(get_mem(insn, &mem)) {
				if(is_same_register_type(mem.base, X86_REG_RSP)) {
					uint8_t size = insn->insn->detail->x86.operands[0].size;
					insn->fake_mem_addr = fake_mem_addr(uc, mem.base, mem.index, mem.scale, size);
				} else {
					insn->fake_mem_addr = fake_mem_addr(uc, mem.base, mem.index, mem.scale, mem.disp);
				}
			}
			insn->fake_mem_addr_2 = fake_mem_addr(uc, base, X86_REG_INVALID, 1, 0);
		}
		//update context (registers and memory will be updated)
		if(is_valid_context(uc, insn)) {
			update_reg(insn);
			update_mem(uc, insn);
			//print context values (registers & memory locations)
			//print_reg_vals();
			//print_mem_vals();
			//end debug
			invalidate_reg(insn, INVALIDATE_PARTIAL);
			invalidate_mem(insn, INVALIDATE_PARTIAL);
		} else {
			update_reg_ref(insn);
			update_mem_ref(uc, insn);
			//print context values (registers & memory locations)
			//print_reg_vals();
			//print_mem_vals();
			//end debug
			invalidate_reg(insn, INVALIDATE_ALL);
			invalidate_mem(insn, INVALIDATE_PARTIAL);
		}
		//print context values (registers & memory locations)
		print_reg_vals();
		print_mem_vals();
		//modify op_str
		update_op_str(uc, insn);
	}
	//go to the next instruction
	current = current->next;
	//dump previous register context
	dump_reg_context(uc, ctx_prev);
}

//NORMAL EMULATION

uint64_t align_addr(uint64_t addr, uint8_t mode) {
	switch(mode) {
		case CS_MODE_32:
			addr &= 0xFFFFF000;
			break;
		case CS_MODE_64:
			addr &= 0xFFFFFFFFFFFFF000;
			break;
	}
	return addr;
}

uint64_t random_reg_value() {
	uint64_t num = rand();
	num = (num << 32 | rand());
	num = (num % (999999999 - 100000000)) + 100000000;
	return num;
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
	//printf("old addr: 0x%llx\n", addr);
	addr = align_addr(addr, MODE);
	//printf("new addr: 0x%llx\n", addr);
	uc_err err;
    switch(type) {
        default:
            //printf("UC_HOOK_MEM_INVALID type: %d at 0x%" PRIx64 "\n", type, addr);
            // map this memory in with 2MB in size
            uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_READ_UNMAPPED:
            //printf("UC_MEM_READ_UNMAPPED at 0x%"PRIx64 ", data size = %u\n", addr, size);
            // map this memory in with 2MB in size
            err = uc_mem_map(uc, addr, 0x1000, UC_PROT_ALL);
			if(err != UC_ERR_OK) {
				if(VERBOSE) printf("[+] Error mapping new READ memory: %s\n", uc_strerror(err));
			}
            // return true to indicate we want to continue
            return true;
        case UC_MEM_WRITE_UNMAPPED:
            //printf("UC_MEM_WRITE_UNMAPPED at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
            // map this memory in with 2MB in size
            uc_mem_map(uc, addr, 0x1000, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_FETCH_PROT:
            //printf("UC_MEM_FETCH_PROT at 0x%"PRIx64 "\n", addr);
            // map this memory in with 2MB in size
            uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_WRITE_PROT:
            //printf("UC_MEM_WRITE_PROT at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
            // map this memory in with 2MB in size
            uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_READ_PROT:
            //printf("UC_MEM_READ_PROT at 0x%"PRIx64 ", data size = %u\n", addr, size);
            // map this memory in with 2MB in size
            uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
    }
}

static bool hook_mem_access(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
	List *mem_list = (List *)user_data;
	switch(type) {
        default: break;
        case UC_MEM_READ:
				//printf(">>> Memory is being READ at 0x%"PRIx64 ", data size = %u\n", addr, size);
				break;
        case UC_MEM_WRITE:
			if(!(addr >= STACK_ADDRESS && addr <= (STACK_ADDRESS + EMU_SIZE))) {
				//if(VERBOSE) printf(">>> Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
				if(mem_list) {
					MemoryValue *mem_val = calloc(1, sizeof(MemoryValue));
					mem_val->address = addr;
					mem_val->value = value;
					mem_val->size = size;
					ListEntry *new_entry = ListEntryCreate(mem_val);
					ListPush(mem_list, new_entry);
				}
			}
			break;
    }
	return true;
}

/*
	Name: print_reg_context
	Description: outputs the register context passed as argument
*/
void print_reg_context(csh handle, Registers *regs, uint8_t mode) {
	printf("\n[!] Register Context\n");
	uint8_t reg_name[0x10] = {
		X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15
	};
	uint32_t count = (mode == CS_MODE_32) ? 8 : 16;
	uint64_t *reg = (uint64_t *)regs;
	for(size_t i = 0; i < count; i++) {
		printf("%s = 0x%lx\n", cs_reg_name(handle, reg_name[i]), reg[i]);
	}
}

/*
	Name: init_regs_context
	Description: this function initializes a registry context given a pointer to the structure
	and a mode (CS_MODE_32 or CS_MODE_64). The stack address is used to initialize the ESP/RSP
	value; the other registers are initialized at random values.
*/
void init_reg_context(Registers **regs, uint64_t stack_address, uint8_t mode) {
	//remember to free the allocation as soon as you don't need it anymore
	*regs = (Registers *)calloc(1, sizeof(Registers));
	//every register is initialized with a random value
	(*regs)->rax = random_reg_value();
	(*regs)->rbx = random_reg_value();
	(*regs)->rcx = random_reg_value();
	(*regs)->rdx = random_reg_value();
	(*regs)->rbp = random_reg_value();
	(*regs)->rsp = stack_address + (stack_address / 2);
	(*regs)->rsi = random_reg_value();
	(*regs)->rdi = random_reg_value();
	//if the mode is CS_MODE_64 also r8-r15 are initialized
	if(mode == CS_MODE_64) {
		(*regs)->r8 = random_reg_value();
		(*regs)->r9 = random_reg_value();
		(*regs)->r10 = random_reg_value();
		(*regs)->r11 = random_reg_value();
		(*regs)->r12 = random_reg_value();
		(*regs)->r13 = random_reg_value();
		(*regs)->r14 = random_reg_value();
		(*regs)->r15 = random_reg_value();
	}
}

/*
	Name: copy_reg_context
	Description: this function copies the registers context from 'old_c' to 'new_c'.
*/
bool copy_reg_context(Registers *old_c, Registers *new_c) {
	if(!old_c) return true;
	if(!new_c) return false;
	//the full x64 context is copied here, also if uninitialized
	memcpy(new_c, old_c, sizeof(Registers));
	return true;
}

/*
	Name: emulate_code
	Description: this function emulates assembly instructions starting from 'start' to 'end'.
	A register context is passed to the function to be used as starting point and updated
	with new values at the emulation end. Also a MemoryLocation list can be passed, and it will
	be updated with address-value of each WRITE.
*/
void emulate_code(csh handle, ListEntry *start, ListEntry *end, Registers *regs, List *mem, List *mem_map, uint8_t mode, bool trace) {
	if(!regs) return;
	//setup constant folding
	if(trace) {
		hndl = handle;
		//setup Registers
		ctx_curr = calloc(1, sizeof(Registers));
		ctx_prev = calloc(1, sizeof(Registers));
		//setup start flag
		first = true;
		//setup first instruction
		current = start;
		//setup registers and memory locations list
		mem_vals = ListCreate();
		reg_vals = ListCreate();
	}
	//generate the byte array to be emulated
	uint64_t assembly_size = 0;
	if(!start) return;
	ListEntry *current = start;
	Instruction *instruction;
	while(current && current != end) {
		instruction = (Instruction *)current->content;
		assembly_size += instruction->insn->size;
		current = current->next;
	}
	uint8_t *assembly = calloc(assembly_size, sizeof(uint8_t));
	current = start;
	uint64_t index = 0;
	while(current && current != end) {
		instruction = (Instruction *)current->content;
		memcpy((assembly + index), instruction->insn->bytes, instruction->insn->size);
		index += instruction->insn->size;
		current = current->next;
	}
	//setup emulation environment
	uc_engine *uc;
	uc_err err;
	err = uc_open(UC_ARCH_X86, mode, &uc);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_open, %s\n", uc_strerror(err));
		return;
	}
	//mapping .text memory, but one should actually allocate every useful piece of memory
	err = uc_mem_map(uc, TEXT_ADDRESS, EMU_SIZE, UC_PROT_ALL);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_mem_map, %s\n", uc_strerror(err));
		return;
	}
	//mapping .stack memory (at a standard address, is not really important to be specific)
	err = uc_mem_map(uc, STACK_ADDRESS, EMU_SIZE, UC_PROT_ALL);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_mem_map, %s\n", uc_strerror(err));
		return;
	}
	//mapping and writing memory values
	if(mem_map) {
		ListEntry *current = mem_map->first;
		MemoryValue *mem_loc;
		while(current) {
			mem_loc = (MemoryValue *)current->content;
			//map the memory
			//if(VERBOSE) printf("uc_mem_map: address (0x%llx), size (0x%llx), value (0x%llx)\n", mem_loc->address, mem_loc->size, mem_loc->value);
			err = uc_mem_map(uc, mem_loc->address, 4096, UC_PROT_ALL);
			if(err != UC_ERR_OK) printf("[-] Error: uc_mem_map, %s!\n", uc_strerror(err));
			//write the value
			err = uc_mem_write(uc, mem_loc->address, (uint8_t *)&(mem_loc->value), mem_loc->size);
			if(err != UC_ERR_OK) printf("[-] Error: uc_mem_write, %s!\n", uc_strerror(err));
			//next MemoryValue
			current = current->next;
		}
	}
	//show the assembly code
	/*if(VERBOSE) {
		printf("Assembly: ");
		for(int i = 0; i < assembly_size; i++) printf("%02X ", assembly[i]);
		printf("\n");
	}*/
	//writing machine code to .text memory
	err = uc_mem_write(uc, TEXT_ADDRESS, assembly, assembly_size);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_mem_write, %s\n", uc_strerror(err));
		return;
	}
	//adding hook to trace-step instructions
	uc_hook hook_id = 0, hook_id_2 = 0, hook_id_3 = 0;
	//trace every instruction (and apply constant folding)
	if(trace) uc_hook_add(uc, &hook_id, UC_HOOK_CODE, hook_code, NULL, TEXT_ADDRESS, TEXT_ADDRESS + assembly_size);
	//intercept invalid memory events
    uc_hook_add(uc, &hook_id_2, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, (uint64_t)1, (uint64_t)0);
    //intercept memory access
    uc_hook_add(uc, &hook_id_3, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, hook_mem_access, mem, (uint64_t)1, (uint64_t)0);
	//write registers to emulation context
	switch(mode) {
		case CS_MODE_32:
			uc_reg_write(uc, UC_X86_REG_EAX, &(regs->rax));
			uc_reg_write(uc, UC_X86_REG_EBX, &(regs->rbx));
			uc_reg_write(uc, UC_X86_REG_ECX, &(regs->rcx));
			uc_reg_write(uc, UC_X86_REG_EDX, &(regs->rdx));
			uc_reg_write(uc, UC_X86_REG_ESP, &(regs->rsp));
			uc_reg_write(uc, UC_X86_REG_EBP, &(regs->rbp));
			uc_reg_write(uc, UC_X86_REG_ESI, &(regs->rsi));
			uc_reg_write(uc, UC_X86_REG_EDI, &(regs->rdi));
			uc_reg_write(uc, UC_X86_REG_EFLAGS, &(regs->eflags));
			break;
		case CS_MODE_64:
			uc_reg_write(uc, UC_X86_REG_RAX, &(regs->rax));
			uc_reg_write(uc, UC_X86_REG_RBX, &(regs->rbx));
			uc_reg_write(uc, UC_X86_REG_RCX, &(regs->rcx));
			uc_reg_write(uc, UC_X86_REG_RDX, &(regs->rdx));
			uc_reg_write(uc, UC_X86_REG_RSP, &(regs->rsp));
			uc_reg_write(uc, UC_X86_REG_RBP, &(regs->rbp));
			uc_reg_write(uc, UC_X86_REG_RSI, &(regs->rsi));
			uc_reg_write(uc, UC_X86_REG_RDI, &(regs->rdi));
			uc_reg_write(uc, UC_X86_REG_R8, &(regs->r8));
			uc_reg_write(uc, UC_X86_REG_R9, &(regs->r9));
			uc_reg_write(uc, UC_X86_REG_R10, &(regs->r10));
			uc_reg_write(uc, UC_X86_REG_R11, &(regs->r11));
			uc_reg_write(uc, UC_X86_REG_R12, &(regs->r12));
			uc_reg_write(uc, UC_X86_REG_R13, &(regs->r13));
			uc_reg_write(uc, UC_X86_REG_R14, &(regs->r14));
			uc_reg_write(uc, UC_X86_REG_R15, &(regs->r15));
			uc_reg_write(uc, UC_X86_REG_EFLAGS, &(regs->eflags));
			break;
	}
	//emulate code
	uint64_t esp = 0;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);
	err = uc_emu_start(uc, TEXT_ADDRESS, TEXT_ADDRESS + assembly_size, 0, 0);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_emu_start, %s\n", uc_strerror(err));
		return;
	}
	//delete hook
	if(trace) uc_hook_del(uc, hook_id);
	uc_hook_del(uc, hook_id_2);
	uc_hook_del(uc, hook_id_3);
	//read registers from emulation context
	switch(mode) {
		case CS_MODE_32:
			uc_reg_read(uc, UC_X86_REG_EAX, &(regs->rax));
			uc_reg_read(uc, UC_X86_REG_EBX, &(regs->rbx));
			uc_reg_read(uc, UC_X86_REG_ECX, &(regs->rcx));
			uc_reg_read(uc, UC_X86_REG_EDX, &(regs->rdx));
			uc_reg_read(uc, UC_X86_REG_ESP, &(regs->rsp));
			uc_reg_read(uc, UC_X86_REG_EBP, &(regs->rbp));
			uc_reg_read(uc, UC_X86_REG_ESI, &(regs->rsi));
			uc_reg_read(uc, UC_X86_REG_EDI, &(regs->rdi));
			uc_reg_read(uc, UC_X86_REG_EFLAGS, &(regs->eflags));
			break;
		case CS_MODE_64:
			uc_reg_read(uc, UC_X86_REG_RAX, &(regs->rax));
			uc_reg_read(uc, UC_X86_REG_RBX, &(regs->rbx));
			uc_reg_read(uc, UC_X86_REG_RCX, &(regs->rcx));
			uc_reg_read(uc, UC_X86_REG_RDX, &(regs->rdx));
			uc_reg_read(uc, UC_X86_REG_RSP, &(regs->rsp));
			uc_reg_read(uc, UC_X86_REG_RBP, &(regs->rbp));
			uc_reg_read(uc, UC_X86_REG_RSI, &(regs->rsi));
			uc_reg_read(uc, UC_X86_REG_RDI, &(regs->rdi));
			uc_reg_read(uc, UC_X86_REG_R8, &(regs->r8));
			uc_reg_read(uc, UC_X86_REG_R9, &(regs->r9));
			uc_reg_read(uc, UC_X86_REG_R10, &(regs->r10));
			uc_reg_read(uc, UC_X86_REG_R11, &(regs->r11));
			uc_reg_read(uc, UC_X86_REG_R12, &(regs->r12));
			uc_reg_read(uc, UC_X86_REG_R13, &(regs->r13));
			uc_reg_read(uc, UC_X86_REG_R14, &(regs->r14));
			uc_reg_read(uc, UC_X86_REG_R15, &(regs->r15));
			uc_reg_read(uc, UC_X86_REG_EFLAGS, &(regs->eflags));
			break;
	}
	//updating memory values
	if(mem_map) {
		ListEntry *current = mem_map->first;
		MemoryValue *mem_loc;
		while(current) {
			mem_loc = (MemoryValue *)current->content;
			//read the updated memory value
			if(uc_mem_read(uc, mem_loc->address, (void *)&(mem_loc->value), mem_loc->size) != UC_ERR_OK) printf("[-] Error: uc_mem_read!\n");
			//next MemoryValue
			current = current->next;
		}
	}
	//freeing assembly
	free(assembly);
	//closing unicorn
	uc_close(uc); //<---- this will break everything, do not enable it
}

/*
	Name: emulate_context
	Description: this function emulates the registry and memory context after the execution of the code
	contained in the List passed as argument. If mod_reg & mem are NULL the context is only displayed
	if the VERBOSE flag is set, and not saved.
*/
void emulate_context(csh handle, List *list, Registers *regs, Registers *mod_regs, List *mem, uint8_t mode) {
	//find which registers are changing
	Registers *old_regs = calloc(1, sizeof(Registers));
	//copying old registers to be able to check after emulation
	copy_reg_context(regs, old_regs);
	//emulate code from first to last instruction
	if(!list || !list->first) {
		printf("[!] WARNING: nothing to emulate, the context is the same!\n");
	} else {
		emulate_code(handle, list->first, list->last->next, regs, mem, NULL, mode, false);
	}
	//check which register is changed and save the instructions modifying it
	uint8_t reg_name[16] = {
		X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15
	};
	if(VERBOSE) printf("\n[!] The following registers are changed\n");
	uint64_t old_reg, new_reg;
	for(size_t i = 0; i < 16; i++) {
		old_reg = (uint64_t)((uint64_t **)old_regs)[i];
		new_reg = (uint64_t)((uint64_t **)regs)[i];
		if(mod_regs) ((uint64_t *)mod_regs)[i] = new_reg;
		if(old_reg != new_reg) {
			if(VERBOSE) printf("%s [OLD = 0x%lx][NEW = 0x%lx]\n", cs_reg_name(handle, reg_name[i]), old_reg, new_reg);
		}
	}
	//reset original regs
	copy_reg_context(old_regs, regs);
	//freeing space
	free(old_regs);
}

/*
	Name: check_context_integrity
	Description: this function does a simple context integrity check, but it does not check the semantic
	of the executed code. Given a knowm and unknown register & memory context, the two are
	compared and if something different is found the result is FALSE.
*/
bool check_context_integrity(Registers *old_regs, List *old_mem, Registers *new_regs, List *new_mem) {
	bool integrity_kept = true, result = false;
	//check first the register context
	if(old_regs && new_regs)
		integrity_kept = (memcmp(old_regs, new_regs, sizeof(Registers)) == 0) ? true : false;
	result = integrity_kept;
	if(!integrity_kept) printf("[!] Lost integrity in the register values!\n");
	/*if(old_mem && new_mem && old_mem->entry_count > 0) {
		printf("old_mem->entry_count %d, new_mem->entry_count: %d\n", old_mem->entry_count, new_mem->entry_count);
		ListEntry *e1, *e2;
		MemoryValue *m1, *m2;
		integrity_kept = true;
		while(integrity_kept && old_mem->entry_count > 0) {
			e1 = (ListEntry *)ListPop(old_mem); e2 = (ListEntry *)ListPop(new_mem);
			m1 = (MemoryValue *)e1->content; m2 = (MemoryValue *)e2->content;
			if(VERBOSE) printf("m1 -> addr = 0x%lx, value = 0x%lx, size = %d\n", m1->address, m1->value, m1->size);
			if(VERBOSE) printf("m2 -> addr = 0x%lx, value = 0x%lx, size = %d\n", m2->address, m2->value, m2->size);
			integrity_kept = ListCmpEntries((void *)e1, (void *)e2, sizeof(MemoryValue));
			if(!integrity_kept) printf("[!] Lost integrity of memory values!\n");
		}
	}*/
	result = integrity_kept;
	return result;
}
