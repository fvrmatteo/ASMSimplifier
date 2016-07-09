/*
	Name: check_regs
	Description: this function will check if 'insn' overwrites one or more registers contained on 'regs_write'.
	If 'insn' reads one o more "valid" registers contained in 'regs_write', the returned value is TRUE.
*/
static bool check_regs(csh handle, Instruction *insn, uint8_t *regs_write, uint8_t regs_write_count) {
	cs_x86 *x86 = &(insn->insn->detail->x86);
	cs_x86_op *op = NULL;
	size_t op_count = x86->op_count;
	//check written registers (using x86 structure)
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_REG) {
			//check if 'op->reg' is contained in 'regs_write'
			for(size_t j = 0; j < regs_write_count; j++) {
				//if(VERBOSE) printf("comparing: %s - %s\n", cs_reg_name(handle, op->reg), cs_reg_name(handle, regs_write[j]));
				if(is_same_register_type(op->reg, regs_write[j])) {
					//check if this instruction also READ the same register
					cs_x86_op *op2 = &(x86->operands[i + 1]);
					if(op_count > 1 && i < op_count && op2->type == X86_OP_REG && (op2->access == CS_AC_READ || op2->access == (CS_AC_READ|CS_AC_WRITE)) && is_same_register_type(op->reg, op2->reg)) {
						return true;
					}
					if(op->access == CS_AC_WRITE) {
						if(is_eq_or_subregister(regs_write[j], op->reg)) regs_write[j] = X86_REG_INVALID;
					} else {
						return true;
					}
				}
			}
		} else if(op->type == X86_OP_MEM) {
			//check if regs_write[j] contains registers used as base/index
			for(size_t j = 0; j < regs_write_count; j++) {
				if(is_same_register_type(op->mem.base, regs_write[j]) || is_same_register_type(op->mem.index, regs_write[j])) {
					return true;
				}
			}
		}
	}
	//check read registers (using 'insn->regs_read')
	uint8_t reg = X86_REG_INVALID;
	size_t rrc = insn->insn->detail->regs_read_count;
	for(size_t i = 0; i < rrc; i++) {
		reg = insn->insn->detail->regs_read[i];
		//check if 'insn->regs_read[i]' is contained in 'regs_read'
		for(size_t j = 0; j < regs_write_count; j++) {
			if(reg != X86_REG_EFLAGS && is_same_register_type(reg, regs_write[j])) return true;
		}
	}
	//check written registers (using 'insn->regs_write')
	size_t rwc = insn->insn->detail->regs_write_count;
	for(size_t i = 0; i < rwc; i++) {
		reg = insn->insn->detail->regs_write[i];
		//check if 'insn->regs_write[i]' is contained in 'regs_write'
		for(size_t j = 0; j < regs_write_count; j++) {
			//if(VERBOSE) printf("comparing: %s - %s\n", cs_reg_name(handle, reg), cs_reg_name(handle, regs_write[j]));
			if(reg != X86_REG_EFLAGS && is_eq_or_subregister(regs_write[j], reg)) regs_write[j] = X86_REG_INVALID;
		}
	}
	return false;
}

/*
	Name: check_mem
	Description: this function will check if 'insn' overwrites the memory location at 'address'.
*/
static bool check_mem(uint8_t access, uint8_t in_size, uint64_t in_address, uint8_t size, uint64_t address, bool *remove_mem) {
	//calculating high & low address for both memory locations
	uint64_t l_a = in_address, h_a = in_address + in_size, l_a_in = address, h_a_in = address + size;
	//comparing the memory locations to check for overlap
	//if((l_a >= l_a_in && l_a <= h_a_in) || (l_a_in >= l_a && l_a_in <= h_a)) {
	if((l_a >= l_a_in && l_a < h_a_in) || (l_a_in >= l_a && l_a_in < h_a)) {
		//a memory overlap is found, check if 'insn' is reading or writing the memory
		if(access == CS_AC_READ || access == (CS_AC_READ|CS_AC_WRITE)) {
			return true;
		} else {
			*remove_mem = true;
			return false;
		}
	}
	return false;
}

/*
	Name: check_eflags
	Description: this function will check if 'insn' overwrites one or more bits contained on 'eflags'.
	If 'insn' reads one o more "valid" bits contained in 'eflags', the returned value is TRUE.
*/
static bool check_eflags(Instruction *insn, uint64_t *eflags) {
	//extract x86 structure
	cs_x86 *x86 = &(insn->insn->detail->x86);
	/*if(VERBOSE) {
		//print 'insn' EFLAGS
		printf("\n'insn' EFLAGS: ");
		for(int i = 0; i <= 45; i++) if(x86->eflags & ((uint64_t)1 << i)) printf(" %s", get_eflag_name((uint64_t)1 << i));
		//print 'before *eflags'
		printf("\nBefore *eflags: ");
		for(int i = 0; i <= 45; i++) if(*eflags & ((uint64_t)1 << i)) printf(" %s", get_eflag_name((uint64_t)1 << i));
	}*/
	//check if the instruction reads valid bits from eflags
	if((x86->eflags & X86_EFLAGS_TEST_OF) && ((*eflags & X86_EFLAGS_MODIFY_OF) || (*eflags & X86_EFLAGS_RESET_OF))) {
		//OF is 'modified' or 'reset' and then 'read'
		return true;
	}
	if((x86->eflags & X86_EFLAGS_TEST_SF) && ((*eflags & X86_EFLAGS_MODIFY_SF) || (*eflags & X86_EFLAGS_RESET_SF))) {
		//SF is 'modified' or 'reset' and then 'read'
		return true;
	}
	if((x86->eflags & X86_EFLAGS_TEST_PF) && ((*eflags & X86_EFLAGS_MODIFY_PF) || (*eflags & X86_EFLAGS_RESET_PF))) {
		//PF is 'modified' or 'reset' and then 'read'
		return true;
	}
	if((x86->eflags & X86_EFLAGS_TEST_CF) && ((*eflags & X86_EFLAGS_MODIFY_CF) || (*eflags & X86_EFLAGS_RESET_CF))) {
		//CF is 'modified' or 'reset' and then 'read'
		return true;
	}
	if((x86->eflags & X86_EFLAGS_TEST_NT) && ((*eflags & X86_EFLAGS_MODIFY_NT) || (*eflags & X86_EFLAGS_RESET_NT))) {
		//NT is 'modified' or 'reset' and then 'read'
		return true;
	}
	if((x86->eflags & X86_EFLAGS_TEST_DF) && ((*eflags & X86_EFLAGS_MODIFY_DF) || (*eflags & X86_EFLAGS_RESET_DF))) {
		//DF is 'modified' or 'reset' and then 'read'
		return true;
	}
	if((x86->eflags & X86_EFLAGS_TEST_ZF) && (*eflags & X86_EFLAGS_MODIFY_ZF)) {
		//ZF is 'modified' or 'reset' and then 'read'
		return true;
	}
	//check if the instruction overwrites valid bits from eflags
	if((x86->eflags & X86_EFLAGS_MODIFY_CF) || (x86->eflags & X86_EFLAGS_RESET_CF) || (x86->eflags & X86_EFLAGS_UNDEFINED_CF) || (x86->eflags & X86_EFLAGS_SET_CF)) {
		//CF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_UNDEFINED_CF | X86_EFLAGS_SET_CF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_OF) || (x86->eflags & X86_EFLAGS_RESET_OF) || (x86->eflags & X86_EFLAGS_UNDEFINED_OF)) {
		//OF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_UNDEFINED_OF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_SF) || (x86->eflags & X86_EFLAGS_RESET_SF) || (x86->eflags & X86_EFLAGS_UNDEFINED_SF)) {
		//SF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_UNDEFINED_SF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_PF) || (x86->eflags & X86_EFLAGS_RESET_PF) || (x86->eflags & X86_EFLAGS_UNDEFINED_PF)) {
		//PF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_UNDEFINED_PF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_AF) || (x86->eflags & X86_EFLAGS_RESET_AF) || (x86->eflags & X86_EFLAGS_UNDEFINED_AF)) {
		//AF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_UNDEFINED_AF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_DF) || (x86->eflags & X86_EFLAGS_RESET_DF) || (x86->eflags & X86_EFLAGS_SET_DF)) {
		//DF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_DF | X86_EFLAGS_RESET_DF | X86_EFLAGS_SET_DF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_IF) || (x86->eflags & X86_EFLAGS_RESET_IF) ||  (x86->eflags & X86_EFLAGS_SET_IF)) {
		//IF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_IF | X86_EFLAGS_RESET_IF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_ZF) || (x86->eflags & X86_EFLAGS_UNDEFINED_ZF)) {
		//ZF is 'modified' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_ZF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_NT) || (x86->eflags & X86_EFLAGS_RESET_NT)) {
		//NT is 'modified' or 'reset', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_NT | X86_EFLAGS_RESET_NT); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_TF) || (x86->eflags & X86_EFLAGS_RESET_TF)) {
		//TF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_TF | X86_EFLAGS_RESET_TF); 
	}
	if((x86->eflags & X86_EFLAGS_MODIFY_RF)) {
		//RF is 'modified' or 'reset' or 'undefined', delete it from *eflags
		*eflags &= ~(X86_EFLAGS_MODIFY_RF);
	}
	/*if(VERBOSE) {
		//print 'before *eflags'
		printf("\nAfter *eflags: ");
		for(int i = 0; i <= 45; i++) if(*eflags & ((uint64_t)1 << i)) printf(" %s", get_eflag_name((uint64_t)1 << i));
		printf("\n");
	}*/
	return false;
}

/*
	Name: get_mem_access
	Description: this function will return the memory access for 'insn'.
*/
static uint8_t get_mem_access(Instruction *insn) {
	cs_x86 *x86 = &(insn->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			return op->access;
		}
	}
	return 0;
}

/*
	Name: isSafe64NopRegOp
	Description: this function will check if a NOP op is valid for x86/x64
*/
static bool isSafe64NopRegOp(uint8_t reg, uint8_t mode) {
	if((mode == CS_MODE_64) && (is_valid(reg) && reg_code(reg) != 0x50)) return false; 
	return true;
}

/*
	Name: is_nop
	Description: this function will identify some known (single) instructions equivalent to NOPs.
*/
static bool is_nop(Instruction *insn, uint8_t mode) {
	//extract x86
	cs_x86 *x86 = &(insn->insn->detail->x86);
	cs_x86_op *ops = x86->operands;
	size_t op_count = x86->op_count;
	//extract 'id' from instruction
	uint32_t id = insn->insn->id;
	//determine if the instruction is a NOP
	switch(id) {
		case X86_INS_NOP:
		case X86_INS_PAUSE:
		case X86_INS_FNOP:
			return true;
		case X86_INS_MOV:
		case X86_INS_CMOVA:
		case X86_INS_CMOVAE:
		case X86_INS_CMOVB:
		case X86_INS_CMOVBE:
		case X86_INS_CMOVE:
		case X86_INS_CMOVNE:
		case X86_INS_CMOVG:
		case X86_INS_CMOVGE:
		case X86_INS_CMOVL:
		case X86_INS_CMOVLE:
		case X86_INS_CMOVO:
		case X86_INS_CMOVNO:
		case X86_INS_CMOVP:
		case X86_INS_CMOVNP:
		case X86_INS_CMOVS:
		case X86_INS_CMOVNS:
		case X86_INS_MOVAPS:
		case X86_INS_MOVAPD:
		case X86_INS_MOVUPS:
		case X86_INS_MOVUPD:
		case X86_INS_XCHG:
			return ops[0].type == X86_OP_REG && ops[1].type == X86_OP_REG && ops[0].reg == ops[1].reg && isSafe64NopRegOp(ops[0].reg, mode);
		case X86_INS_LEA: {
			return ops[0].type == X86_OP_REG && ops[1].type == X86_OP_MEM && ops[1].mem.disp == 0 &&
				   ((ops[1].mem.index == X86_REG_INVALID && ops[1].mem.base == ops[0].reg) ||
					(ops[1].mem.index == ops[0].reg && ops[1].mem.base == X86_REG_INVALID && ops[1].mem.scale == 1)) && isSafe64NopRegOp(ops[0].reg, mode);
		}
		case X86_INS_JMP:
		case X86_INS_JA:
		case X86_INS_JAE:
		case X86_INS_JB:
		case X86_INS_JBE:
		case X86_INS_JE:
		case X86_INS_JNE:
		case X86_INS_JG:
		case X86_INS_JGE:
		case X86_INS_JL:
		case X86_INS_JLE:
		case X86_INS_JO:
		case X86_INS_JNO:
		case X86_INS_JP:
		case X86_INS_JNP:
		case X86_INS_JS:
		case X86_INS_JNS:
		case X86_INS_JECXZ:
		case X86_INS_JCXZ:
		case X86_INS_LOOP:
		case X86_INS_LOOPE:
		case X86_INS_LOOPNE:
			return ops[0].type == X86_OP_IMM && ops[0].imm == 0;
		case X86_INS_SHL:
		case X86_INS_SHR:
		case X86_INS_ROL:
		case X86_INS_ROR:
		case X86_INS_SAR:
		case X86_INS_SAL:
		case X86_INS_SUB:
		case X86_INS_ADD:
			return op_count == 2 && ops[1].type == X86_OP_IMM && ops[1].imm == 0 && isSafe64NopRegOp(ops[0].reg, mode);
		case X86_INS_SHLD:
		case X86_INS_SHRD:
			return ops[2].type == X86_OP_IMM && ops[2].imm == 0 && isSafe64NopRegOp(ops[0].reg, mode) && isSafe64NopRegOp(ops[1].reg, mode);
		default:
			return false;
	}
}

/*
	Name: is_useless
	Description: this function will check if 'current' is a useless instruction that can be removed without
	problems from the Assembly listing. Various checks are made to determine if the instruction is useless.
*/
static bool is_useless(csh handle, ListEntry *current, uint8_t mode) {
	if(!current || !current->content) return false;
	//extract instruction
	Instruction *insn = (Instruction *)current->content;
	cs_x86 *x86 = &(insn->insn->detail->x86);
	size_t op_count = x86->op_count, regs_write_count = insn->insn->detail->regs_write_count;
	//check if the instruction is useless (NOP-like) -> some instructions behave like NOP
	if(is_nop(insn, mode)) return true;
	//check if the instruction is useless (NOP-like) -> does not uses/modifies register/memory
	if(op_count == 0 && regs_write_count == 0/* && x86->eflags == 0*/) return true;
	//check if the instruction sets a reg/mem overwritten by another instruction before being read.
	uint8_t regs_write[6], write_counter = 0;
	cs_x86_op *op;
	//extract written registers (using x86 structure)
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if((op->access == CS_AC_WRITE || op->access == (CS_AC_WRITE|CS_AC_READ)) && op->type == X86_OP_REG) {
			regs_write[write_counter++] = op->reg;
		}
	}
	//extract written registers (using regs_write array)
	uint8_t reg = X86_REG_INVALID;
	for(size_t i = 0; i < regs_write_count; i++) {
		reg = insn->insn->detail->regs_write[i];
		if(reg != X86_REG_EFLAGS) regs_write[write_counter++] = reg;
	}
	//extract written EFLAGS bits
	uint64_t eflags = x86->eflags;
	//determine if the instructions is a "memory instruction" and extract the memory size
	MemoryLocation mem_loc_in;
	//bool is_mem_ins = (is_memory_insn(insn) && !cmp_id(insn->insn->id, X86_INS_LEA));
	bool is_mem_ins = ((get_dst_mem(insn, &mem_loc_in, CS_AC_WRITE) || get_dst_mem(insn, &mem_loc_in, CS_AC_READ|CS_AC_WRITE)) && !cmp_id(insn->insn->id, X86_INS_LEA));
	uint8_t mem_size; if(is_mem_ins) get_mem_size(insn, &mem_size);
	//now we need to scan the following instructions to know if 'regs_write' are overwritten (before beign read)
	ListEntry *next = current->next;
	Instruction *curr_ins = NULL;
	bool all_invalid = false;
	while(next) {
		//extract current instruction
		curr_ins = (Instruction *)next->content;
		if(VERBOSE) print_insn("\tTesting: ", curr_ins);
		//check if the instruction reads or overwrites entirely the memory location
		if(is_mem_ins) {
			bool remove_mem = false;
			if(is_memory_insn(curr_ins) && !cmp_id(insn->insn->id, X86_INS_LEA) && !cmp_mnemonic(curr_ins->insn->mnemonic, "push") && !cmp_mnemonic(curr_ins->insn->mnemonic, "pop")) {
				uint8_t size; get_mem_size(curr_ins, &size);
				printf("Checking memory: 0x%lx == 0x%lx\n", curr_ins->fake_mem_addr, insn->fake_mem_addr);
				if(check_mem(get_mem_access(curr_ins), size, curr_ins->fake_mem_addr, mem_size, insn->fake_mem_addr, &remove_mem)) {
					return false;
				} else if(remove_mem) {
					return true;
				}
			} else if(cmp_mnemonic(curr_ins->insn->mnemonic, "push")) {
				//check if this is PUSH [MEM], it could be [MEM] is READ
				if(is_memory_insn(curr_ins)) {
					if(check_mem(get_mem_access(curr_ins), curr_ins->insn->detail->x86.operands[0].size, curr_ins->fake_mem_addr_2, mem_size, insn->fake_mem_addr, &remove_mem)) {
						return false;
					} else if(remove_mem) {
						return true;
					}
				}
				//check if the instruction overwrites entirely the memory location (PUSH)
				if(check_mem(CS_AC_WRITE, curr_ins->insn->detail->x86.operands[0].size, curr_ins->fake_mem_addr, mem_size, insn->fake_mem_addr, &remove_mem)) {
					return false;
				} else if(remove_mem) {
					return true; 
				}
			} else if(cmp_mnemonic(curr_ins->insn->mnemonic, "pop")) {
				//check if the instruction reads the memory location (POP)
				if(is_memory_insn(curr_ins)) {
					//this is a: POP [MEM] for now ignore it
					return false;
				} else if(check_mem(CS_AC_READ, curr_ins->insn->detail->x86.operands[0].size, curr_ins->fake_mem_addr, mem_size, insn->fake_mem_addr, &remove_mem)) {
					return false;
				} else if(remove_mem) {
					return true;
				}
			}
		} else if(cmp_id(curr_ins->insn->id, X86_INS_LEA)) {
			//check if base/index is equals to the destination register
			cs_x86 *x86_t = &(curr_ins->insn->detail->x86);
			size_t op_cnt = x86_t->op_count;
			cs_x86_op *op_t = NULL;
			for(size_t i = 0; i < op_cnt; i++) {
				op_t = &(x86_t->operands[i]);
				if(op_t->type == X86_OP_MEM) {
					for(size_t j = 0; j < write_counter; j++) {
						if(is_same_register_type(op_t->mem.base, regs_write[j]) || is_same_register_type(op_t->mem.index, regs_write[j])) return false;
					}
				}
			}
		}
		//check if the instruction overwrites all the registers in 'regs_write'
		if(write_counter > 0 && check_regs(handle, curr_ins, regs_write, write_counter)) {
			return false;
		} else if(write_counter > 0) {
			all_invalid = true;
			//check if 'regs_write' contains only X86_REG_INVALID, it means every register is overwritten
			for(size_t i = 0; i < write_counter && all_invalid; i++) if(regs_write[i] != X86_REG_INVALID) all_invalid = false;
			if(all_invalid) return true;
		} else {
			//there are no written registers, so we can set 'all_invalid' to true
			all_invalid = true;
		}
		//check if the instruction overwrites all the bits of EFLAGS
		if(check_eflags(curr_ins, &eflags)) { return false; } else { if(eflags == 0 && all_invalid && !is_mem_ins) return true; }
		//go to next instructions
		next = next->next;
	}
	return false;
}

/*
	Name: dead_code_elimination
	Description: this function will delete all useless instructions in an Assembly listing.
*/
bool dead_code_elimination(csh handle, List *list, uint8_t mode) {
	bool optimized = false;
	if(!list || !list->first) return optimized;
	//useful variables
	ListEntry *current = list->first;
	Instruction *insn = NULL;
	//loop all instructions and remove useless ones
	while(current) {
		//extract instruction
		insn = (Instruction *)current->content;
		if(VERBOSE) print_insn("Checking: ", insn);
		//ignore XCHG / PUSH / POP instructions
		if(cmp_id(insn->insn->id, X86_INS_XCHG) || cmp_mnemonic(insn->insn->mnemonic, "push") || cmp_mnemonic(insn->insn->mnemonic, "pop")) {
			current = current->next;
			continue;
		}
		//check if it is useless
		if(is_useless(handle, current, mode)) {
			//remove the instruction
			if(!cmp_id(insn->insn->id, X86_INS_NOP)) {
				//debug
				if(VERBOSE) print_insn("[!] Removing useless instruction: ", current->content);
				if(NO_NOP) {
					ListRemove(list, current);
				} else {
					RemoveWithNop(list, current, mode);
				}
				//notify as optimized
				optimized = true;
			}
		}
		//go to next instruction
		current = current->next;
	}
	return optimized;
}