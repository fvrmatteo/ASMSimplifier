bool is_valid(uint8_t reg) {
	return (reg != X86_REG_INVALID);
}

uint8_t register_type(uint8_t reg) {
	uint8_t register_type = -1, register_code = 0x60;
	/*
		register_code:

		RAX = 0x50
		EAX = 0x40
		AX = 0x30
		AH = 0x20
		AL = 0x10
	*/
	/*
		register_type:

		RAX = 0x0
		RBX = 0x1
		RCX = 0x2
		RDX = 0x3
		RSP = 0x4
		RBP = 0x5
		RSI = 0x6
		RDI = 0x7
		R8 = 0x8
		R9 = 0x9
		R10 = 0xa
		R11 = 0xb
		R12 = 0xc
		R13 = 0xd
		R14 = 0xe
		R15 = 0xf
	*/
	switch(reg) {
		case X86_REG_AL:
			register_code -= 0x10;
		case X86_REG_AH:
			register_code -= 0x10;
		case X86_REG_AX:
			register_code -= 0x10;
		case X86_REG_EAX:
			register_code -= 0x10;
		case X86_REG_RAX:
			register_code -= 0x10;
			register_type = 0x0;
			break;
		case X86_REG_BL:
			register_code -= 0x10;
		case X86_REG_BH:
			register_code -= 0x10;
		case X86_REG_BX:
			register_code -= 0x10;
		case X86_REG_EBX:
			register_code -= 0x10;
		case X86_REG_RBX:
			register_code -= 0x10;
			register_type = 0x1;
			break;
		case X86_REG_CL:
			register_code -= 0x10;
		case X86_REG_CH:
			register_code -= 0x10;
		case X86_REG_CX:
			register_code -= 0x10;
		case X86_REG_ECX:
			register_code -= 0x10;
		case X86_REG_RCX:
			register_code -= 0x10;
			register_type = 0x2;
			break;
		case X86_REG_DL:
			register_code -= 0x10;
		case X86_REG_DH:
			register_code -= 0x10;
		case X86_REG_DX:
			register_code -= 0x10;
		case X86_REG_EDX:
			register_code -= 0x10;
		case X86_REG_RDX:
			register_code -= 0x10;
			register_type = 0x3;
			break;
		case X86_REG_SPL:
			register_code -= 0x10;
		case X86_REG_SP:
			register_code -= 0x10;
		case X86_REG_ESP:
			register_code -= 0x10;
		case X86_REG_RSP:
			register_code -= 0x10;
			register_type = 0x4;
			break;
		case X86_REG_BPL:
			register_code -= 0x10;
		case X86_REG_BP:
			register_code -= 0x10;
		case X86_REG_EBP:
			register_code -= 0x10;
		case X86_REG_RBP:
			register_code -= 0x10;
			register_type = 0x5;
			break;
		case X86_REG_SIL:
			register_code -= 0x10;
		case X86_REG_SI:
			register_code -= 0x10;
		case X86_REG_ESI:
			register_code -= 0x10;
		case X86_REG_RSI:
			register_code -= 0x10;
			register_type = 0x6;
			break;
		case X86_REG_DIL:
			register_code -= 0x10;
		case X86_REG_DI:
			register_code -= 0x10;
		case X86_REG_EDI:
			register_code -= 0x10;
		case X86_REG_RDI:
			register_code -= 0x10;
			register_type = 0x7;
			break;
		case X86_REG_R8B:
			register_code -= 0x20;
		case X86_REG_R8W:
			register_code -= 0x10;
		case X86_REG_R8D:
			register_code -= 0x10;
		case X86_REG_R8:
			register_code -= 0x10;
			register_type = 0x8;
			break;
		case X86_REG_R9B:
			register_code -= 0x20;
		case X86_REG_R9W:
			register_code -= 0x10;
		case X86_REG_R9D:
			register_code -= 0x10;
		case X86_REG_R9:
			register_code -= 0x10;
			register_type = 0x9;
			break;
		case X86_REG_R10B:
			register_code -= 0x20;
		case X86_REG_R10W:
			register_code -= 0x10;
		case X86_REG_R10D:
			register_code -= 0x10;
		case X86_REG_R10:
			register_code -= 0x10;
			register_type = 0xa;
			break;
		case X86_REG_R11B:
			register_code -= 0x20;
		case X86_REG_R11W:
			register_code -= 0x10;
		case X86_REG_R11D:
			register_code -= 0x10;
		case X86_REG_R11:
			register_code -= 0x10;
			register_type = 0xb;
			break;
		case X86_REG_R12B:
			register_code -= 0x20;
		case X86_REG_R12W:
			register_code -= 0x10;
		case X86_REG_R12D:
			register_code -= 0x10;
		case X86_REG_R12:
			register_code -= 0x10;
			register_type = 0xc;
			break;
		case X86_REG_R13B:
			register_code -= 0x20;
		case X86_REG_R13W:
			register_code -= 0x10;
		case X86_REG_R13D:
			register_code -= 0x10;
		case X86_REG_R13:
			register_code -= 0x10;
			register_type = 0xd;
			break;
		case X86_REG_R14B:
			register_code -= 0x20;
		case X86_REG_R14W:
			register_code -= 0x10;
		case X86_REG_R14D:
			register_code -= 0x10;
		case X86_REG_R14:
			register_code -= 0x10;
			register_type = 0xe;
			break;
		case X86_REG_R15B:
			register_code -= 0x20;
		case X86_REG_R15W:
			register_code -= 0x10;
		case X86_REG_R15D:
			register_code -= 0x10;
		case X86_REG_R15:
			register_code -= 0x10;
			register_type = 0xf;
			break;
		//handle EFLAGS + others
		//case X86_REG_EFLAGS:
		//	register_code = 0xf;
		//	register_type = 0xf;
		default:
			break;	
	}
	return (register_code | register_type);
}

uint8_t reg_code(uint8_t reg) {
	if(reg == X86_REG_EFLAGS) {
		//printf("WARNING: requesting EFLAGS reg_code!\n");
		return -1;
	}
	return register_type(reg) & 0xF0;
}

bool is_eq_or_subsize(uint8_t reg1, uint8_t reg2) {
	if((reg_code(reg1) == 0x20 && reg_code(reg2) == 0x10) || (reg_code(reg1) == 0x10 && reg_code(reg2) == 0x20)) {
		printf("Example: BH and BL are not comparable in size.\n");
		return false;
	}
	return reg_code(reg1) <= reg_code(reg2);
}

uint8_t reg_type(uint8_t reg) {
	if(reg == X86_REG_EFLAGS) {
		//printf("WARNING: requesting EFLAGS reg_type!\n");
		return 0x10;
	}
	return register_type(reg) & 0xF;
}

uint8_t register_from_code(uint8_t code_type) {
	uint8_t type = code_type & 0xF, code = code_type & 0xF0, reg = X86_REG_INVALID;
	//printf("type: 0x%llx\n", type);
	//printf("code: 0x%llx\n", code);
	/*
		register_code:

		RAX = 0x50
		EAX = 0x40
		AX = 0x30
		AH = 0x20
		AL = 0x10
	*/
	/*
		register_type:

		RAX = 0x0
		RBX = 0x1
		RCX = 0x2
		RDX = 0x3
		RSP = 0x4
		RBP = 0x5
		RSI = 0x6
		RDI = 0x7
		R8 = 0x8
		R9 = 0x9
		R10 = 0xa
		R11 = 0xb
		R12 = 0xc
		R13 = 0xd
		R14 = 0xe
		R15 = 0xf
	*/
	switch(type) {
		case 0:
			switch(code) {
				case 0x10:
					reg = X86_REG_AL;
					break;
				case 0x20:
					reg = X86_REG_AH;
					break;
				case 0x30:
					reg = X86_REG_AX;
					break;
				case 0x40:
					reg = X86_REG_EAX;
					break;
				case 0x50:
					reg = X86_REG_RAX;
					break;
			}
			break;
		case 1:
			switch(code) {
				case 0x10:
					reg = X86_REG_BL;
					break;
				case 0x20:
					reg = X86_REG_BH;
					break;
				case 0x30:
					reg = X86_REG_BX;
					break;
				case 0x40:
					reg = X86_REG_EBX;
					break;
				case 0x50:
					reg = X86_REG_RBX;
					break;
			}
			break;
		case 2:
			switch(code) {
				case 0x10:
					reg = X86_REG_CL;
					break;
				case 0x20:
					reg = X86_REG_CH;
					break;
				case 0x30:
					reg = X86_REG_CX;
					break;
				case 0x40:
					reg = X86_REG_ECX;
					break;
				case 0x50:
					reg = X86_REG_RCX;
					break;
			}
			break;
		case 3:
			switch(code) {
				case 0x10:
					reg = X86_REG_DL;
					break;
				case 0x20:
					reg = X86_REG_DH;
					break;
				case 0x30:
					reg = X86_REG_DX;
					break;
				case 0x40:
					reg = X86_REG_EDX;
					break;
				case 0x50:
					reg = X86_REG_RDX;
					break;
			}
			break;
		case 4:
			switch(code) {
				case 0x10:
					reg = X86_REG_SPL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_SP;
					break;
				case 0x40:
					reg = X86_REG_ESP;
					break;
				case 0x50:
					reg = X86_REG_RSP;
					break;
			}
			break;
		case 5:
			switch(code) {
				case 0x10:
					reg = X86_REG_BPL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_BP;
					break;
				case 0x40:
					reg = X86_REG_EBP;
					break;
				case 0x50:
					reg = X86_REG_RBP;
					break;
			}
			break;
		case 6:
			switch(code) {
				case 0x10:
					reg = X86_REG_SIL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_SI;
					break;
				case 0x40:
					reg = X86_REG_ESI;
					break;
				case 0x50:
					reg = X86_REG_RSI;
					break;
			}
			break;
		case 7:
			switch(code) {
				case 0x10:
					reg = X86_REG_DIL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_DI;
					break;
				case 0x40:
					reg = X86_REG_EDI;
					break;
				case 0x50:
					reg = X86_REG_RDI;
					break;
			}
			break;
		case 8:
			switch(code) {
				case 0x10:
					reg = X86_REG_R8B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R8W;
					break;
				case 0x40:
					reg = X86_REG_R8D;
					break;
				case 0x50:
					reg = X86_REG_R8;
					break;
			}
			break;
		case 9:
			switch(code) {
				case 0x10:
					reg = X86_REG_R9B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R9W;
					break;
				case 0x40:
					reg = X86_REG_R9D;
					break;
				case 0x50:
					reg = X86_REG_R9;
					break;
			}
			break;
		case 0xa:
			switch(code) {
				case 0x10:
					reg = X86_REG_R10B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R10W;
					break;
				case 0x40:
					reg = X86_REG_R10D;
					break;
				case 0x50:
					reg = X86_REG_R10;
					break;
			}
			break;
		case 0xb:
			switch(code) {
				case 0x10:
					reg = X86_REG_R11B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R11W;
					break;
				case 0x40:
					reg = X86_REG_R11D;
					break;
				case 0x50:
					reg = X86_REG_R11;
					break;
			}
			break;
		case 0xc:
			switch(code) {
				case 0x10:
					reg = X86_REG_R12B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R12W;
					break;
				case 0x40:
					reg = X86_REG_R12D;
					break;
				case 0x50:
					reg = X86_REG_R12;
					break;
			}
			break;
		case 0xd:
			switch(code) {
				case 0x10:
					reg = X86_REG_R13B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R13W;
					break;
				case 0x40:
					reg = X86_REG_R13D;
					break;
				case 0x50:
					reg = X86_REG_R13;
					break;
			}
			break;
		case 0xe:
			switch(code) {
				case 0x10:
					reg = X86_REG_R14B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R14W;
					break;
				case 0x40:
					reg = X86_REG_R14D;
					break;
				case 0x50:
					reg = X86_REG_R14;
					break;
			}
			break;
		case 0xf:
			switch(code) {
				case 0x10:
					reg = X86_REG_R15B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R15W;
					break;
				case 0x40:
					reg = X86_REG_R15D;
					break;
				case 0x50:
					reg = X86_REG_R15;
					break;
			}
			break;
	}
	return reg;
}

bool is_same_register_type(uint8_t reg1, uint8_t reg2) {
	if(!is_valid(reg1) || !is_valid(reg2)) return false;
	return ((register_type(reg1) & 0xF) == (register_type(reg2) & 0xF));
}

bool is_eq_or_subregister(uint8_t reg1, uint8_t reg2) {
	uint8_t reg1_type = register_type(reg1);
	uint8_t reg2_type = register_type(reg2);
	//printf("comparing: %d <= %d", reg1_type, reg2_type);
	//check for valid register_type
	if(reg1_type == -1 || reg2_type == -1) return false;
	//check for equality
	if(reg1_type == reg2_type) return true;
	//if both reg1_type & reg2_type are AL | AH the check must fail.
	if((((reg1_type & 0xf0) == 0x10) || ((reg1_type & 0xf0) == 0x20)) && (((reg2_type & 0xf0) == 0x10) || ((reg2_type & 0xf0) == 0x20))) {
		return false;
	}
	//normal check: if they are the same register type and reg1 is a subregister of reg2
	if(is_same_register_type(reg1, reg2) && reg1_type < reg2_type) return true;
	return false;
}

bool is_segment_reg(uint8_t reg) {
	switch(reg) {
		case X86_REG_CS:
		case X86_REG_SS:
		case X86_REG_DS:
		case X86_REG_ES:
		case X86_REG_FS:
		case X86_REG_GS:
			return true;
	}
	return false;
}

uint64_t resize_immediate(uint64_t imm, uint8_t reg) {
	uint8_t reg_code = register_type(reg) & 0xF0;
	switch(reg_code) {
		case 0x10:
			imm &= 0xFF;
			break;
		case 0x30:
			imm &= 0xFFFF;
			break;
		case 0x40:
			imm &= 0xFFFFFFFF;
			break;
	}
	return imm;
}

uint64_t res_imm(uint64_t imm, uint8_t bytes) {
	switch(bytes) {
		case 1:
			imm &= 0xFF;
			break;
		case 2:
			imm &= 0xFFFF;
			break;
		case 4:
			imm &= 0xFFFFFFFF;
			break;
	}
	return imm;
}

uint8_t res_reg(uint8_t reg, uint8_t bytes) {
	reg = reg_type(reg);
	switch(bytes) {
		case 1:
			reg |= 0x10;
			break;
		case 2:
			reg |= 0x30;
			break;
		case 4:
			reg |= 0x40;
			break;
		case 8:
			reg |= 0x50;
			break;
	}
	return register_from_code(reg);
}

char *get_eflag_name(uint64_t flag) {
	switch(flag) {
		default:
			return NULL;
		case X86_EFLAGS_UNDEFINED_OF:
			return "UNDEF_OF";
		case X86_EFLAGS_UNDEFINED_SF:
			return "UNDEF_SF";
		case X86_EFLAGS_UNDEFINED_ZF:
			return "UNDEF_ZF";
		case X86_EFLAGS_MODIFY_AF:
			return "MOD_AF";
		case X86_EFLAGS_UNDEFINED_PF:
			return "UNDEF_PF";
		case X86_EFLAGS_MODIFY_CF:
			return "MOD_CF";
		case X86_EFLAGS_MODIFY_SF:
			return "MOD_SF";
		case X86_EFLAGS_MODIFY_ZF:
			return "MOD_ZF";
		case X86_EFLAGS_UNDEFINED_AF:
			return "UNDEF_AF";
		case X86_EFLAGS_MODIFY_PF:
			return "MOD_PF";
		case X86_EFLAGS_UNDEFINED_CF:
			return "UNDEF_CF";
		case X86_EFLAGS_MODIFY_OF:
			return "MOD_OF";
		case X86_EFLAGS_RESET_OF:
			return "RESET_OF";
		case X86_EFLAGS_RESET_CF:
			return "RESET_CF";
		case X86_EFLAGS_RESET_DF:
			return "RESET_DF";
		case X86_EFLAGS_RESET_IF:
			return "RESET_IF";
		case X86_EFLAGS_TEST_OF:
			return "TEST_OF";
		case X86_EFLAGS_TEST_SF:
			return "TEST_SF";
		case X86_EFLAGS_TEST_ZF:
			return "TEST_ZF";
		case X86_EFLAGS_TEST_PF:
			return "TEST_PF";
		case X86_EFLAGS_TEST_CF:
			return "TEST_CF";
		case X86_EFLAGS_RESET_SF:
			return "RESET_SF";
		case X86_EFLAGS_RESET_AF:
			return "RESET_AF";
		case X86_EFLAGS_RESET_TF:
			return "RESET_TF";
		case X86_EFLAGS_RESET_NT:
			return "RESET_NT";
		case X86_EFLAGS_PRIOR_OF:
			return "PRIOR_OF";
		case X86_EFLAGS_PRIOR_SF:
			return "PRIOR_SF";
		case X86_EFLAGS_PRIOR_ZF:
			return "PRIOR_ZF";
		case X86_EFLAGS_PRIOR_AF:
			return "PRIOR_AF";
		case X86_EFLAGS_PRIOR_PF:
			return "PRIOR_PF";
		case X86_EFLAGS_PRIOR_CF:
			return "PRIOR_CF";
		case X86_EFLAGS_PRIOR_TF:
			return "PRIOR_TF";
		case X86_EFLAGS_PRIOR_IF:
			return "PRIOR_IF";
		case X86_EFLAGS_PRIOR_DF:
			return "PRIOR_DF";
		case X86_EFLAGS_TEST_NT:
			return "TEST_NT";
		case X86_EFLAGS_TEST_DF:
			return "TEST_DF";
		case X86_EFLAGS_RESET_PF:
			return "RESET_PF";
		case X86_EFLAGS_PRIOR_NT:
			return "PRIOR_NT";
		case X86_EFLAGS_MODIFY_TF:
			return "MOD_TF";
		case X86_EFLAGS_MODIFY_IF:
			return "MOD_IF";
		case X86_EFLAGS_MODIFY_DF:
			return "MOD_DF";
		case X86_EFLAGS_MODIFY_NT:
			return "MOD_NT";
		case X86_EFLAGS_MODIFY_RF:
			return "MOD_RF";
		case X86_EFLAGS_SET_CF:
			return "SET_CF";
		case X86_EFLAGS_SET_DF:
			return "SET_DF";
		case X86_EFLAGS_SET_IF:
			return "SET_IF";
	}
}

uint8_t resize_reg(uint8_t reg1, uint8_t reg2) {
	//check if reg1 <= reg2, in this case we don't need to resize reg1
	if(is_eq_or_subsize(reg1, reg2)) return reg1;
	//otherwise we need to resize it, get reg_type from reg1 & reg_code from reg2
	return register_from_code(reg_code(reg2) | reg_type(reg1));
}