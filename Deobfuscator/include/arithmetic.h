/*
	Name: check_reg
	Description: this function will determine if 'reg' is R/W by 'insn'.
*/
static bool check_reg(Instruction *insn, uint8_t reg) {
	cs_x86 *x86 = &(insn->insn->detail->x86);
	cs_x86_op *op;
	size_t op_count = x86->op_count;
	uint64_t imm;
	//check reg R/W using x86 structure
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_REG) {
			if(op->access == CS_AC_READ && is_same_register_type(reg, op->reg)) {
				return false;
			} else if(op->access == CS_AC_WRITE && is_eq_or_subregister(reg, op->reg)) {
				return false;
			} else if(op->access == (CS_AC_READ|CS_AC_WRITE) && is_eq_or_subregister(reg, op->reg)) {
				//this means the register is updated with an unknown value
				if(!get_imm(insn, &imm, NULL) && op_count > 1) return false;
			}
		} else if(op->type == X86_OP_MEM) {
			if(is_same_register_type(reg, op->mem.base) || is_same_register_type(reg, op->mem.index)) {
				return false;
			}
		}
	}
	//check reg R using 'regs_read' array
	uint8_t tmp_reg = X86_REG_INVALID;
	size_t rrc = insn->insn->detail->regs_read_count;
	for(size_t i = 0; i < rrc; i++) {
		tmp_reg = insn->insn->detail->regs_read[i];
		if(tmp_reg != X86_REG_EFLAGS && is_same_register_type(reg, tmp_reg)) return false;
	}
	//check reg W using 'regs_write' array
	size_t rwc = insn->insn->detail->regs_write_count;
	for(size_t i = 0; i < rwc; i++) {
		tmp_reg = insn->insn->detail->regs_write[i];
		if(tmp_reg != X86_REG_EFLAGS && is_eq_or_subregister(reg, tmp_reg)) return false; 
	}
	return true;
}

/*
	Name: is_reg_updated
	Description: this function will check if 'reg' is updated by 'insn'.
*/
static bool is_reg_updated(Instruction *insn, uint8_t reg) {
	uint8_t curr_reg; get_dst_reg(insn, &curr_reg, NULL, CS_AC_READ|CS_AC_WRITE);
	return is_same_register_type(curr_reg, reg);
	//we need to check if the update happens on a equal or smaller register
	//return is_eq_or_subregister(curr_reg, reg);
}

/*
	Name: check_mem
	Description: this function will determine if 'mem' is R/W by 'insn'.
*/
static bool check_memory(Instruction *insn, MemoryLocation *mem) {
	mem->seg = 0;
	MemoryLocation mem_loc;
	if(get_src_mem(insn, &mem_loc)) {
		mem_loc.seg = 0;
		if(memcmp(&mem_loc, mem, sizeof(MemoryLocation)) == 0) return false;
	} else if(get_dst_mem(insn, &mem_loc, CS_AC_WRITE)) {
		mem_loc.seg = 0;
		if(memcmp(&mem_loc, mem, sizeof(MemoryLocation)) == 0) return false;
	}
	return true;
}

/*
	Name: is_mem_updated
	Description: this function will determine if 'mem' is updated by 'insn'.
*/
static bool is_mem_updated(Instruction *insn, MemoryLocation *mem) {
	mem->seg = 0;
	MemoryLocation mem_loc;
	if(get_dst_mem(insn, &mem_loc, CS_AC_READ|CS_AC_WRITE)) {
		if(memcmp(&mem_loc, mem, sizeof(MemoryLocation)) == 0) return true;
	}
	return false;
}

/*
	Name: add_insn
	Description: this function will add 'insn' into a list that will be used as emulation list.
*/
static void add_insn(List *emu_list, Instruction *insn) {
	ListEntry *new_entry = calloc(1, sizeof(ListEntry));
	new_entry->content = insn;
	ListPush(emu_list, new_entry);
}

/*
	Name: create_fake_insn
	Description: this function will create a fake instruction to be used on emulation.
*/
static Instruction *create_fake_insn(csh handle, Instruction *insn, uint8_t mode) {
	char *op_str;
	//change register/memory with a default register RAX
	uint8_t dst_reg = X86_REG_INVALID;
	if(get_dst_reg(insn, &dst_reg, NULL, CS_AC_WRITE) || get_dst_reg(insn, &dst_reg, NULL, CS_AC_READ|CS_AC_WRITE)) {
		//if a register is used, change it with RAX (or EAX, AX, AH, AL)
		op_str = str_replace(insn->insn->op_str, (char *)cs_reg_name(handle, dst_reg), (char *)cs_reg_name(handle, resize_reg(X86_REG_RAX, dst_reg)), -1);
	} else {
		//if a memory location is used, change it with RAX (or EAX, AX, AH, AL)
		uint64_t imm;
		uint8_t size; get_mem_size(insn, &size);
		op_str = calloc(20, sizeof(char));
		if(get_imm(insn, &imm, NULL)) {
			if(get_dst_reg(insn, NULL, NULL, CS_AC_WRITE) || get_dst_reg(insn, NULL, NULL, CS_AC_READ|CS_AC_WRITE) || get_mem(insn, NULL)) {
				sprintf(op_str, "%s, 0x%lx", cs_reg_name(handle, res_reg(X86_REG_RAX, size)), imm);
			} else {
				sprintf(op_str, "0x%lx", imm);
			}
		} else {
			sprintf(op_str, "%s", cs_reg_name(handle, res_reg(X86_REG_RAX, size)));
		}
	}
	//assemble new instruction
	Instruction *new_insn = assemble_insn(insn->insn->mnemonic, op_str, (uint64_t)NULL, mode);
	if(VERBOSE) print_insn("Fake insn: ", new_insn);
	return new_insn;
}

static uint64_t extract_reg_val(uint64_t val, uint8_t reg) {
	uint8_t reg_c = reg_code(reg);
	switch(reg_c) {
		case 0x10: return (val & 0xFF);
		case 0x20: return ((val & 0xFF00) >> 8);
		case 0x30: return (val & 0xFFFF);
		case 0x40: return (val & 0xFFFFFFFF);
		default: return val;
	}
}

/*
	Name: arithmetic_solver
	Description: this function will find and solve arithmetic sequences in the Assembly listing.
*/
bool arithmetic_solver(csh handle, List *list, uint8_t mode) {
	bool optimized = false;
	if(!list || !list->first) return optimized;
	//scan and simplify all arithmetic instructions
	ListEntry *current = list->first, *mov = NULL;
	Instruction *insn = NULL;
	//useful variables
	bool init_found = false, op_done = false, valid = true;
	uint64_t imm = 0, imm_op = 0;
	uint8_t reg = X86_REG_INVALID;
	MemoryLocation mem;
	Registers regs;
	//emulation list
	List *emu_list;
	while(current) {
		//reset flags
		valid = true;
		//extract instruction
		insn = (Instruction *)current->content;
		if(VERBOSE) print_insn("Checking: ", insn);
		//check if the mnemonic is 'MOV'
		if(!init_found && cmp_id(insn->insn->id, X86_INS_MOV)) {
			//check if the source is an immediate
			if(get_imm(insn, &imm, NULL)) {
				//check if the destination is a register or a memory location
				if(get_dst_reg(insn, &reg, NULL, CS_AC_WRITE) || get_dst_mem(insn, &mem, CS_AC_WRITE)) {
					//notify we found something interesting
					init_found = true;
					op_done = false;
					//save MOV address, to remove it later
					mov = current;
					//save 'mov' instruction into the emulation list
					//if(emu_list) ListDestroy(emu_list);
					emu_list = ListCreate();
					//add instruction to the list
					add_insn(emu_list, create_fake_insn(handle, insn, mode));
					//go to the next instruction
					current = current->next;
					continue;
				}
			}
		}
		//check if this is another MOV after the previous MOV
		if(!op_done && init_found && cmp_id(insn->insn->id, X86_INS_MOV) && (!check_reg(insn, reg) || !check_memory(insn, &mem))) {
			init_found = false;
			continue;
		}
		//check if this instruction updates 'reg' or 'mem'
		if(init_found) {
			//extract current id
			uint32_t id = get_id(insn);
			imm_op = 1;
			//check if this instruction overwrites/read 'reg' or 'mem'
			if(reg != X86_REG_INVALID) {
				//we are looking for register updates, check if 'reg' is updated using an immediate
				if((valid = check_reg(insn, reg)) && is_reg_updated(insn, reg) && (cmp_id(id, X86_INS_DEC) || cmp_id(id, X86_INS_INC) || cmp_id(id, X86_INS_NOT) || cmp_id(id, X86_INS_NEG) || cmp_id(id, X86_INS_BSWAP) || get_imm(insn, &imm_op, NULL))) {
					//extract the instruction ID and update 'imm'
					add_insn(emu_list, create_fake_insn(handle, insn, mode));
					//remove useless instruction
					ListRemove(list, current);
					//notify we did an operation
					op_done = true;
				} else {
					//insert new instruction
					if(op_done) {
						//we reached the last useful instruction, we can now emulate
						if(VERBOSE) {
							printf("Going to emulate:\n");
							print_disassembly(handle, emu_list, false);
						}
						emulate_code(handle, emu_list->first, NULL, &regs, NULL, NULL, mode, false);
						//assemble new instruction
						ListRemove(list, mov);
						ListEntry *entry = calloc(1, sizeof(ListEntry));
						Instruction *new_ins = calloc(1, sizeof(Instruction));
						new_ins->insn = calloc(1, sizeof(cs_insn));
						sprintf(new_ins->insn->mnemonic, "mov");
						sprintf(new_ins->insn->op_str, "%s, 0x%lx", cs_reg_name(handle, reg), extract_reg_val(regs.rax, reg));
						new_ins = assemble_insn(new_ins->insn->mnemonic, new_ins->insn->op_str, insn->insn->address, mode);
						if(VERBOSE) print_insn("Assembled: ", new_ins);
						entry->content = new_ins;
						ListInsertBefore(list, current, entry);
						//reset 'op_done'
						op_done = false;
						//reset init_found
						init_found = false;
					}
					//reset 'init_found' if the instruction is invalidated
					if(!valid) init_found = false;
				}
			} else {
				//we are looking for memory updates, check if 'mem' is updated using an immediate
				if(is_mem_updated(insn, &mem) && check_memory(insn, &mem) && (cmp_id(id, X86_INS_DEC) || cmp_id(id, X86_INS_INC) || cmp_id(id, X86_INS_NOT) || cmp_id(id, X86_INS_BSWAP) || get_imm(insn, &imm_op, NULL))) {
					//add instruction to 'emu_list'
					add_insn(emu_list, create_fake_insn(handle, insn, mode));
					//remove useless instruction
					ListRemove(list, current);
					//notify we did an operation
					op_done = true;
				} else {
					//we reached the last useful instruction, we can now emulate
					if(VERBOSE) {
						printf("Going to emulate:\n");
						print_disassembly(handle, emu_list, false);
					}
					emulate_code(handle, emu_list->first, NULL, &regs, NULL, NULL, mode, false);
					//assemble new instruction
					if(op_done) {
						ListRemove(list, mov);
						ListEntry *entry = calloc(1, sizeof(ListEntry));
						Instruction *new_ins = calloc(1, sizeof(Instruction));
						new_ins->insn = calloc(1, sizeof(cs_insn));
						sprintf(new_ins->insn->mnemonic, "mov");
						sprintf(new_ins->insn->op_str, "%s ptr [%s], 0x%lx", get_mem_indicator(mem.size), fix_mem_op_str(handle, mem.base, mem.index, mem.scale, mem.disp), (mode == CS_MODE_32) ? regs.rax &= 0xFFFFFFFF : regs.rax);
						new_ins = assemble_insn(new_ins->insn->mnemonic, new_ins->insn->op_str, insn->insn->address, mode);
						if(VERBOSE) print_insn("Assembled: ", new_ins);
						entry->content = new_ins;
						ListInsertBefore(list, current, entry);
						//reset 'op_done'
						op_done = false;
					}
					//we found an instruction reading or overwriting 'mem'
					init_found = false;
				}
			}
		}
		//go to the next instruction
		current = current->next;
		//if we reached the end and 'op_done' is true, emulate it and assemble the new instruction
		if(op_done && !current) {
			//we reached the last useful instruction, we can now emulate
			if(VERBOSE) {
				printf("Going to emulate:\n");
				print_disassembly(handle, emu_list, false);
			}
			emulate_code(handle, emu_list->first, NULL, &regs, NULL, NULL, mode, false);
			//assemble new instruction
			ListEntry *entry = calloc(1, sizeof(ListEntry));
			Instruction *new_ins = calloc(1, sizeof(Instruction));
			new_ins->insn = calloc(1, sizeof(cs_insn));
			sprintf(new_ins->insn->mnemonic, "mov");
			if(is_memory_insn(mov->content)) {
				sprintf(new_ins->insn->op_str, "%s ptr [%s], 0x%lx", get_mem_indicator(mem.size), fix_mem_op_str(handle, mem.base, mem.index, mem.scale, mem.disp), (mode == CS_MODE_32) ? regs.rax &= 0xFFFFFFFF : regs.rax);
			} else {
				sprintf(new_ins->insn->op_str, "%s, 0x%lx", cs_reg_name(handle, reg), (mode == CS_MODE_32) ? regs.rax &= 0xFFFFFFFF : regs.rax);
			}
			ListRemove(list, mov);
			new_ins = assemble_insn(new_ins->insn->mnemonic, new_ins->insn->op_str, insn->insn->address, mode);
			if(VERBOSE) print_insn("Assembled: ", new_ins);
			entry->content = new_ins;
			if(list->last) {
				ListInsertAfter(list, list->last, entry);
			} else {
				ListPush(list, entry);
			}
		}
	}
	return optimized;
}

/*
	Name: update_sum
	Description: this function will update the sum based on the ID.
*/
static void update_sum(uint64_t *sum, uint32_t id, uint64_t imm) {
	switch(id) {
		case X86_INS_MOV:
		case X86_INS_ADD: *sum += imm; break;
		case X86_INS_SUB: *sum -= imm; break;
	}
}

/*
	Name: memory_used
	Description: this function will check if the memory is used by the instruction.
*/
static bool memory_used(Instruction *insn, uint64_t fake_mem_addr, MemoryLocation *mem) {
	MemoryLocation curr_mem;
	if(get_mem(insn, &curr_mem)) {
		uint64_t l_in = fake_mem_addr, h_in = fake_mem_addr + mem->size;
		uint64_t l = insn->fake_mem_addr, h = insn->fake_mem_addr + curr_mem.size;
		if((l_in >= l && l_in < h) || (l >= l_in && l < h_in)) return true;
	} else if(cmp_mnemonic(insn->insn->mnemonic, "push") || cmp_mnemonic(insn->insn->mnemonic, "pop")) {
		if(insn->fake_mem_addr == fake_mem_addr) return true;
	}
	return false;
}

/*
	Name: collapse_add_sub_2
	Description: this function will collapse all the add/sub sequences, on both registers and memory locations.
*/
bool collapse_add_sub_2(csh handle, List *list, uint8_t mode) {
	bool optimized = false;
	if(!list || !list->first) return optimized;
	//search for add-sub and collapse them
	ListEntry *current = list->first, *tmp_curr_next = NULL;
	Instruction *insn = NULL;
	uint64_t imm = 0, sum = 0, counter = 0;
	bool is_mov = false;
	while(current) {
		//reset flags
		is_mov = false;
		//save current next instruction
		tmp_curr_next = current->next;
		//extract instruction
		insn = (Instruction *)current->content;
		//debug
		if(VERBOSE) print_insn("Current add/sub: ", insn);
		//check if this instruction is 'add' or 'sub' and is using an immediate value
		if((cmp_id(insn->insn->id, X86_INS_ADD) || cmp_id(insn->insn->id, X86_INS_SUB) || cmp_id(insn->insn->id, X86_INS_MOV)) && get_imm(insn, &imm, NULL)) {
			//debug
			if(cmp_id(insn->insn->id, X86_INS_MOV)) is_mov = true;
			//reset the sum and the counter to zero
			counter = sum = 0;
			//save register or memory location
			uint8_t dst_reg = X86_REG_INVALID;
			MemoryLocation dst_mem;
			//using a flag to know if it's memory or register
			bool is_reg = false, is_mem = false;
			//extract destination
			if(get_dst_reg(insn, &dst_reg, NULL, CS_AC_READ|CS_AC_WRITE)) {
				is_reg = true;
			} else if(get_dst_mem(insn, &dst_mem, CS_AC_READ|CS_AC_WRITE)) {
				is_mem = true;
			}
			//update the sum
			update_sum(&sum, insn->insn->id, imm);
			//useful variables
			uint8_t curr_reg = X86_REG_INVALID;
			MemoryLocation curr_mem;
			//collapse it until possible
			ListEntry *next = current->next, *tmp_next;
			Instruction *curr_insn = NULL;
			//trace when something is collapsed or invalidated
			bool collapsed = false, invalidated = false;
			while(next) {
				//reset flags
				invalidated = collapsed = false;
				//save current next instruction
				tmp_next = next->next;
				//extract instruction
				curr_insn = (Instruction *)next->content;
				//debug
				if(VERBOSE) print_insn("\tadd/sub: ", curr_insn);
				//check if this instruction is 'add' or 'sub' and is using an immediate value
				if((cmp_id(curr_insn->insn->id, X86_INS_ADD) || cmp_id(curr_insn->insn->id, X86_INS_SUB))) {
					//check if the instruction is using an immediate
					if(!get_imm(curr_insn, &imm, NULL)) {
						next = tmp_next;
						continue;
					}
					//check if the memory location or the register is the one we are looking for
					bool is_curr_reg = false, is_curr_mem = false;
					//extract destination
					if(get_dst_reg(curr_insn, &curr_reg, NULL, CS_AC_READ|CS_AC_WRITE)) {
						is_curr_reg = true;
					} else if(get_dst_mem(curr_insn, &curr_mem, CS_AC_READ|CS_AC_WRITE)) {
						is_curr_mem = true;
					}
					//check if it is valid
					if(is_reg && is_curr_reg) {
						//check if the register is the same (or less big)
						if(is_eq_or_subregister(curr_reg, dst_reg)) collapsed = true;
					} else if(is_mem && is_curr_mem) {
						//check if the memory is the same (or less big)
						if((insn->fake_mem_addr == curr_insn->fake_mem_addr) && (curr_mem.size <= dst_mem.size)) collapsed = true;
					}
				}
				//execute the collapse or stop the search
				if(collapsed) {
					//increment the counter
					counter++;
					//we can update the sum
					update_sum(&sum, curr_insn->insn->id, imm);
					//we can remove the useless add/sub instruction
					ListRemove(list, next);
				} else {
					//check if this instruction is invalidating or reading the register or the memory location
					if(is_reg) {
						//check if this instruction is reading or invalidating the register
						if(!check_reg(curr_insn, dst_reg) || is_reg_updated(curr_insn, dst_reg)) invalidated = true;
					} else {
						//check if this instruction is reading or invalidating the memory location
						if(memory_used(curr_insn, insn->fake_mem_addr, &dst_mem)) invalidated = true;
						//extract modified registers and check if base or index are affected
						cs_x86 *x86_tmp = &(curr_insn->insn->detail->x86);
						size_t op_count_tmp = x86_tmp->op_count;
						cs_x86_op *op_tmp;
						for(size_t i = 0; i < op_count_tmp && !invalidated; i++) {
							op_tmp = &(x86_tmp->operands[i]);
							if(op_tmp->type == X86_OP_REG && (op_tmp->access == CS_AC_WRITE || op_tmp->access == (CS_AC_READ|CS_AC_WRITE))) {
								if(is_same_register_type(dst_mem.base, op_tmp->reg) || is_same_register_type(dst_mem.index, op_tmp->reg)) invalidated = true;
							}
						}
						size_t regs_write_count_tmp = curr_insn->insn->detail->regs_write_count;
						uint8_t dst_reg_tmp;
						for(size_t i = 0; i < regs_write_count_tmp && !invalidated; i++) {
							dst_reg_tmp = curr_insn->insn->detail->regs_write[i];
							if(is_same_register_type(dst_mem.base, dst_reg_tmp) || is_same_register_type(dst_mem.index, dst_reg_tmp)) invalidated = true;
						}
					}
				}
				//if the add/sub sequence is invalidated or we reached the end, generate the new instruction
				if((invalidated || !tmp_next) && counter > 0) {
					//assemble the new instruction
					char op_str[160];
					if(is_reg) {
						//resize the 'sum' value
						sum = resize_immediate(sum, dst_reg);
						sprintf(op_str, "%s, 0x%lx", cs_reg_name(handle, dst_reg), sum);
					} else {
						//resize the 'sum' value
						sum = res_imm(sum, dst_mem.size);
						sprintf(op_str, "%s ptr [%s], 0x%lx", get_mem_indicator(dst_mem.size), fix_mem_op_str(handle, dst_mem.base, dst_mem.index, dst_mem.scale, dst_mem.disp), sum);
					}
					Instruction *new_insn = assemble_insn((is_mov) ? "mov" : "add", op_str, insn->insn->address, mode);
					ListEntry *entry = calloc(1, sizeof(ListEntry));
					//copy memory address from the original instruction
					new_insn->fake_mem_addr = curr_insn->fake_mem_addr;
					new_insn->fake_mem_addr_2 = curr_insn->fake_mem_addr_2;
					entry->content = new_insn;
					//insert instruction into the list
					ListInsertAfter(list, current, entry);
					//remove original add/sub instruction
					ListRemove(list, current);
					//update tmp_curr_next
					tmp_curr_next = tmp_next;
					//exit from inner while
					tmp_next = NULL;
				} else if(invalidated) {
					//exit from inner while
					tmp_next = NULL;
				}
				//check the next instruction
				next = tmp_next;
			}
		}
		//check the next instruction
		current = tmp_curr_next;
	}
	return optimized;
}