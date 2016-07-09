#include <math.h>

/*
 ___________________________________________________________
|___________________________________________________________|
|															|
|	NOTA1 OTTIMIZZAZIONE:									|
|		una volta creato un match bisogna inserirlo in		|
|		un array in modo che sia facilmente recuperabile.	|
|															|
|															|
|	NOTA2 FEATURE:											|
|		aggiungere la lista per escludere alcuni registri.	|
|___________________________________________________________|
|___________________________________________________________|

*/

//useful structures and union
typedef union Val {
	char *op;
	uint8_t reg;
	uint64_t imm;
	MemoryLocation mem;
} Val;

typedef struct ValCouple {
	char *name;
	Val val;
} ValCouple;

typedef struct PeepMatch {
	//these lists contains instructions/registers
	List *insn_list;
	List *no_first_reg;
	List *no_second_reg;
	//List *no_third_reg; UNUSED FOR NOW
	
	//these variables keep track of the names associated with operands/instructions
	char *insn_name;
	char *first_reg_name;
	char *second_reg_name;
	//char *third_reg_name; UNUSED FOR NOW
	char *mem_name;
	char *imm_name;
	char *mem_sz_str;
	
	//these variables keep track of the operands values
	uint8_t first_reg;
	uint8_t second_reg;
	//uint8_t third_reg; UNUSED FOR NOW
	uint64_t imm;
	int32_t mem_disp_off;
	MemoryLocation mem;
	
	//these variables keep the operands size (the memory size is already contained in MemoryLocation
	uint8_t first_reg_sz;
	uint8_t second_reg_sz;
	uint8_t imm_sz;
	
	//string for instruction manipulation
	char *update_imm_str;
	
	//this flag is used to specify if we want to check the mnemonic
	bool check_mnemonic;
	bool global_mem;	//THIS IS USELESS
	bool mem_disp_off_enabled;
	
	//these flags are used to specify which operands are enabled
	bool first_reg_enabled;
	bool second_reg_enabled;
	bool imm_enabled;
	bool mem_enabled;
	
	//these flags are used to specify if we know the value of 'imm' or 'mem'
	bool imm_known;
	bool mem_known;
	
	//these flags are used to specify detailed information about registers/memory locations/immediate
	bool check_first_reg_size;
	bool check_second_reg_size;
	bool check_third_reg_size;
	bool check_imm_size;
	bool check_size;
	bool check_base;
	bool check_index;
	bool check_scale;
	bool check_disp;
} PeepMatch;

typedef struct PeepPattern {
	List *pat_list;	//contains a list of instructions to look for in the Assembly listing
	List *rep_list;	//contains the replaced "optimized" instructions
} PeepPattern;

typedef struct ConcurrentMatch {
	ListEntry *next_match;	//pointer to the next pattern
	PeepMatch *match;		//pointer to the current PeepMatch
	List *known_val;		//pointer to the current known_val
	List *ins_list;			//pointer to the list containing matched instructions
	List *rep_list;			//pointer to the list containing replacement instructions
	bool invalid;			//this indicates if the match is valid
	bool advance;			//this indicates if the match needs to be advanced
	size_t match_count;		//this indicates how many matches are completed
} ConcurrentMatch;

//This is the list containing each patterns sequence, each entry is a PeepPattern.
//It is initialized at program start reading the file 'peephole.pat'.
//More patterns can be added to the file by the user.
List *patterns;

static size_t read_line(char *line, char *buffer, size_t max, char separator) {
	size_t i;
	for(i = 0; i < max; i++) {
		if(buffer[i] == separator || buffer[i] == '\0') break;
		line[i] = buffer[i];
	}
	//always put an C-String end character
	line[i] = '\0';
	//the number of read character is returned
	return i;
}

//useful functions
static bool get_value(List *known_val, char *id, Val *val) {
	if(!known_val || !known_val->first) return false;
	ListEntry *next = known_val->first;
	ValCouple *couple;
	while(next) {
		couple = (ValCouple *)next->content;
		if(strncmp(couple->name, id, strlen(id)) == 0) {
			switch(id[0]) {
				case 'r': val->reg = couple->val.reg; break;
				case 'i': val->imm = couple->val.imm; break;
				case 'm': {
					val->mem.size = couple->val.mem.size;
					val->mem.base = couple->val.mem.base;
					val->mem.index = couple->val.mem.index;
					val->mem.scale = couple->val.mem.scale;
					val->mem.disp = couple->val.mem.disp;
					break;
				}
			}
			return true;
		}
		next = next->next;
	}
	return false;
}

static uint8_t get_reg_from_name(csh handle, char *name) {
	//THIS MUST BE IMPLEMENTED AS O(1) WITH AN HASHMAP (but for now it is ok)
	//check if name is a tag, like 'reg1' or 'reg2'
	if(strncmp(name, "reg", 3) == 0) return X86_REG_INVALID;
	uint8_t regs[68] = { 
		X86_REG_AL, X86_REG_AH, X86_REG_AX, X86_REG_EAX, X86_REG_RAX,
		X86_REG_BL, X86_REG_BH, X86_REG_BX, X86_REG_EBX, X86_REG_RBX,
		X86_REG_CL, X86_REG_CH, X86_REG_CX, X86_REG_ECX, X86_REG_RCX,
		X86_REG_DL, X86_REG_DH, X86_REG_DX, X86_REG_EDX, X86_REG_RDX,
		X86_REG_SIL, X86_REG_SI, X86_REG_ESI, X86_REG_RSI,
		X86_REG_DIL, X86_REG_DI, X86_REG_EDI, X86_REG_RDI,
		X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP,
		X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP,
		X86_REG_R8B, X86_REG_R8W, X86_REG_R8D, X86_REG_R8,
		X86_REG_R9B, X86_REG_R9W, X86_REG_R9D, X86_REG_R9,
		X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10,
		X86_REG_R11B, X86_REG_R11W, X86_REG_R11D, X86_REG_R11,
		X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12,
		X86_REG_R13B, X86_REG_R13W, X86_REG_R13D, X86_REG_R13,
		X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14,
		X86_REG_R15B, X86_REG_R15W, X86_REG_R15D, X86_REG_R15
	};
	for(int i = 0; i < sizeof(regs); i++) if(strcmp(name, cs_reg_name(handle, regs[i])) == 0) return regs[i];
	return X86_REG_INVALID;
}

static bool check_access(List *known_val, uint8_t reg, uint8_t type) {
	if(!known_val || !known_val->first) return false;
	ListEntry *entry = known_val->first;
	ValCouple *val;
	while(entry) {
		val = (ValCouple *)entry->content;
		switch(val->name[0]) {
			case 'w':
				if(is_same_register_type(val->val.reg, reg)) return true;
				break;
			case 'r':
				if(is_same_register_type(val->val.reg, reg)) return true;
				break;
			case 'm':
				if(type == CS_AC_WRITE || type == (CS_AC_WRITE|CS_AC_READ)) {
					if(is_same_register_type(val->val.mem.base, reg)) return true;
					if(is_same_register_type(val->val.mem.index, reg)) return true;
				}
				break;
		}
		entry = entry->next;
	}
	return false;
}

static size_t num_sequence_alive(List *concurrent_list, ListEntry *first_ins) {
	size_t num = 0;
	ListEntry *next = concurrent_list->first, *ins;
	ConcurrentMatch *match;
	while(next) {
		match = (ConcurrentMatch *)next->content;
		if(!match->invalid && match->match_count > 0) {
			ins = match->ins_list->first->content;
			if(ins == first_ins) {
				//print_insn("first_ins: ", first_ins->content);
				//print_insn("first_matched: ", ins->content);
				num++;
			} else {
				//invalidate this because we are not interested in matches not starting from the first instruction
				match->invalid = true;
			}
		} else {
			match->invalid = true;
		}
		next = next->next;
	}
	return num;
}

static void remove_tabs(char **line) {
	while(**line == '\t') (*line)++;
}

static void init_patterns() {
	//open peephole.pat file, it contains pattern signatures
	FILE *pat = fopen("peephole.new", "r");
	if(!pat) {
		printf("[-] 'peephole.pat' file not found.\n");
		exit(-1);
	}
	//initialize patterns' list
	PeepPattern *pattern = NULL;
	patterns = ListCreate();
	//read each line, made by: a comment, a pattern sequence, a replacement sequence
	size_t read, size = 0xFF;
	char *line = calloc(size, sizeof(char)), *pat_str = NULL, *rep_str = NULL, *line_cp = NULL;
	bool match_found = false, replace_found = false;
	//read semi-XML pattern
	while((read = getline(&line, &size, pat)) != -1) {
		//copy line address
		line_cp = line;
		//delete all TABs
		remove_tabs(&line_cp);
		//match the semi-XML token
		if(strncmp(line_cp, "<match>", 7) == 0) {
			//initialize a new string (medium string 10 * 255 characters)
			pat_str = calloc(10 * 0xFF, sizeof(char));
			//notify we found a match
			match_found = true;
		} else if(strncmp(line_cp, "</match>", 8) == 0) {
			//resize the string containing the pattern sequence
			pat_str = realloc(pat_str, strlen(pat_str) + 1);
			//save the pattern sequence string
			ListPush(pattern->pat_list, ListEntryCreate(pat_str));
			//notify the match is now closed
			match_found = false;
		} else if(strncmp(line_cp, "<replace>", 9) == 0) {
			//notify we found a replace
			replace_found = true;
		} else if(strncmp(line_cp, "</replace>", 10) == 0) {
			//notify the replace is now closed
			replace_found = false;
		} else if(strncmp(line_cp, "<pattern>", 9) == 0) {
			//initialize a new pattern
			pattern = calloc(1, sizeof(PeepPattern));
			pattern->pat_list = ListCreate();
			pattern->rep_list = ListCreate();
		} else if(strncmp(line_cp, "</pattern>", 10) == 0) {
			//insert a new pattern sequence in the list
			if(pattern) ListPush(patterns, ListEntryCreate(pattern));
		} else {
			if(match_found) {
				//concatenate this line to pat_str
				pat_str = strcat(pat_str, line_cp);
			} else if(replace_found) {
				//insert a new replace string in the list
				if(strncmp(line_cp, "<rep_str>", 9) == 0) {
					rep_str = str_between(line_cp, "<rep_str>", "</rep_str>");
					ListPush(pattern->rep_list, ListEntryCreate(rep_str));
				}
			} else {
				//this line is ignored
			}
		}
	}
	//free line
	free(line);
	//close peephole.pat file
	fclose(pat);
}

static PeepMatch *create_insn_match(csh handle, char *match_string, List *known_val, uint8_t mode) {
	//allocate space for a new PeepMatch
	PeepMatch *match = calloc(1, sizeof(PeepMatch));
	//variables to create PeepMatch
	Val val;
	//variables to read each line of pseudo-XML
	size_t max = 0xFF, read = 0, tot_read = 0; char line[max], *between = NULL;
	while((read = read_line(line, match_string + tot_read, max, '\n'))) {
		//highly inefficient (but easy to read) strncmp-if
		if(strncmp(line, "<insn>", 6) == 0) {
			//extract the string between <insn>string</insn>
			between = str_between(line, "<insn>", "</insn>");
			//allocate new space for the instruction list
			match->insn_list = ListCreate();
			//we found an instruction marker, extract the instruction list
			size_t count = 0, count_tot = 0, ins_len = 10; char *insn = calloc(ins_len, sizeof(char));
			while((count = read_line(insn, between + count_tot, ins_len, ','))) {
				//resize memory
				insn = realloc(insn, count);
				//save mnemonic
				ListPush(match->insn_list, ListEntryCreate(insn));
				//allocate a new string
				insn = calloc(ins_len, sizeof(char));
				//increment count_tot
				count_tot += (count + 1);
			}
			//mark we are going to check the mnemonic
			match->check_mnemonic = true;
		} else if(strncmp(line, "<ins_name>", 10) == 0) {
			//extract the string between <insn_name>string</insn_name>
			between = str_between(line, "<ins_name>", "</ins_name>");
			//allocate space for the instruction name
			match->insn_name = calloc(strlen(between) + 1, sizeof(char));
			//save the instruction name
			memcpy(match->insn_name, between, strlen(between));
		} else if(strncmp(line, "<first_reg>", 11) == 0) {
			//extract the string between <first_reg>string</first_reg>
			between = str_between(line, "<first_reg>", "</first_reg>");
			//check if we know the register value
			if(get_value(known_val, between, &val)) {
				match->first_reg = val.reg;
			} else {
				//setup register name
				if(strncmp(between, "stack", 5) == 0) {
					//determine which stack register to use
					match->first_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
					//generate first register name
					char stack[10]; sprintf(stack, "%s", cs_reg_name(handle, match->first_reg));
					//allocate space for the first register name
					match->first_reg_name = calloc(strlen(stack) + 1, sizeof(char));
					//save first register name
					memcpy(match->first_reg_name, stack, strlen(stack));
				} else {
					//determine register from name
					match->first_reg = get_reg_from_name(handle, between);
					//allocate space for the first register name
					match->first_reg_name = calloc(strlen(between) + 1, sizeof(char));
					//save first register name
					memcpy(match->first_reg_name, between, strlen(between));
				}
			}
			//mark the first register as enabled
			match->first_reg_enabled = true;
		} else if(strncmp(line, "<first_reg_exclude>", 19) == 0) {
			//extract the string between <first_reg_exclude>string</first_reg_exclude>
			between = str_between(line, "<first_reg_exclude>", "</first_reg_exclude>");
			//allocate new space for the first_reg_exclude list
			match->no_first_reg = ListCreate();
			//we found a register marker, extract the exclude list
			size_t count = 0, count_tot = 0, reg_len = 5; char *reg = calloc(reg_len, sizeof(char));
			while((count = read_line(reg, between + count_tot, reg_len, ','))) {
				//resize memory
				reg = realloc(reg, count);
				//save register
				ListPush(match->no_first_reg, ListEntryCreate(reg));
				//allocate a new string
				reg = calloc(reg_len, sizeof(char));
				//increment count_tot
				count_tot += (count + 1);
			}
		} else if(strncmp(line, "<first_reg_size>", 16) == 0) {
			//extract the string between <first_reg>string</first_reg>
			between = str_between(line, "<first_reg_size>", "</first_reg_size>");
			//save the register size
			match->first_reg_sz = atoi(between);
			//mark the first register size as enabled
			match->check_first_reg_size = true;
		} else if(strncmp(line, "<second_reg>", 12) == 0) {
			//extract the string between <first_reg>string</first_reg>
			between = str_between(line, "<second_reg>", "</second_reg>");
			//check if we know the register value
			if(get_value(known_val, between, &val)) {
				match->second_reg = val.reg;
			} else {
				//setup register name
				if(strncmp(between, "stack", 5) == 0) {
					//determine which stack register to use
					match->second_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
					//generate second register name
					char stack[10]; sprintf(stack, "%s", cs_reg_name(handle, match->second_reg));
					//allocate space for the second register name
					match->second_reg_name = calloc(strlen(stack) + 1, sizeof(char));
					//save second register name
					memcpy(match->second_reg_name, stack, strlen(stack));
				} else {
					//determine register from name
					match->second_reg = get_reg_from_name(handle, between);
					//allocate space for the second register name
					match->second_reg_name = calloc(strlen(between) + 1, sizeof(char));
					//save second register name
					memcpy(match->second_reg_name, between, strlen(between));
				}
			}
			//mark the source register as enabled
			match->second_reg_enabled = true;
		} else if(strncmp(line, "<second_reg_exclude>", 20) == 0) {
			//extract the string between <second_reg_exclude>string</second_reg_exclude>
			between = str_between(line, "<second_reg_exclude>", "</second_reg_exclude>");
			//allocate new space for the second_reg_exclude list
			match->no_second_reg = ListCreate();
			//we found a register marker, extract the exclude list
			size_t count = 0, count_tot = 0, reg_len = 5; char *reg = calloc(reg_len, sizeof(char));
			while((count = read_line(reg, between + count, reg_len, ','))) {
				//resize memory
				reg = realloc(reg, count);
				//save register
				ListPush(match->no_second_reg, ListEntryCreate(reg));
				//allocate a new string
				reg = calloc(reg_len, sizeof(char));
				//increment count_tot
				count_tot += (count + 1);
			}
		} else if(strncmp(line, "<second_reg_size>", 17) == 0) {
			//extract the string between <first_reg>string</first_reg>
			between = str_between(line, "<second_reg_size>", "</second_reg_size>");
			//save the register size
			match->second_reg_sz = atoi(between);
			//mark the second register size as enabled
			match->check_second_reg_size = true;
		} else if(strncmp(line, "<imm>", 5) == 0) {
			//extract string between <imm>string</imm>
			between = str_between(line, "<imm>", "</imm>");
			//check if we already know the immediare value
			if(get_value(known_val, between, &val)) {
				match->imm_known = true;
				match->imm = val.imm;
			} else if(strncmp(between, "imm", 3) != 0) {
				match->imm_known = true;
				match->imm = atoi(between);
			} else {
				//allocate space for immediate name
				match->imm_name = calloc(strlen(between) + 1, sizeof(char));
				//save memory name
				memcpy(match->imm_name, between, strlen(between));
			}
			//mark the immediate as enabled
			match->imm_enabled = true;
		} else if(strncmp(line, "<imm_size>", 10) == 0) {
			//extract string between <imm_size>string</imm_size>
			between = str_between(line, "<imm_size>", "</imm_size>");
			//save immediate size
			match->imm_sz = atoi(between);
			//mark the immediate size as enabled
			match->check_imm_size = true;
		} else if(strncmp(line, "<update_imm>", 12) == 0) {
			//extract string between <update_imm>string</update_imm>
			between = str_between(line, "<update_imm>", "</update_imm>");
			//allocate space for the immediate update string
			match->update_imm_str = calloc(strlen(between) + 1, sizeof(char));
			//save the simple computation string
			memcpy(match->update_imm_str, between, strlen(between));
		} else if(strncmp(line, "<mem>", 5) == 0) {
			//extract string between <mem>string</mem>
			between = str_between(line, "<mem>", "</mem>");
			//check if the memory value is known
			if(get_value(known_val, between, &val)) {
				match->mem_known = true;
				match->mem.size = val.mem.size;
				match->mem.base = val.mem.base;
				match->mem.index = val.mem.index;
				match->mem.scale = val.mem.scale;
				match->mem.disp = val.mem.disp;
			} else {
				//allocate space for the memory name
				match->mem_name = calloc(strlen(between) + 1, sizeof(char));
				//save memory name
				memcpy(match->mem_name, between, strlen(between));
			}
			//mark the memory as enabled
			match->mem_enabled = true;
			match->global_mem = true;
		} else if(strncmp(line, "<mem_size>", 10) == 0) {
			//extract string between <mem_size>string</mem_size>
			between = str_between(line, "<mem_size>", "</mem_size>");
			//save memory size
			if(between[0] == '?') {
				match->mem.size = 0;
				match->check_size = false;
			} else {
				match->mem.size = atoi(between);
				match->check_size = true;
			}
			//mark the memory size as enabled
			match->mem_enabled = true;
			match->mem_known = true;
		} else if(strncmp(line, "<mem_base>", 10) == 0) {
			//extract string between <mem_base>string</mem_base>
			between = str_between(line, "<mem_base>", "</mem_base>");
			//check if the stack register is used
			if(between[0] == '?') {
				match->mem.base = X86_REG_INVALID;
				match->check_base = false;
			} else {
				if(strncmp(between, "stack", 5) == 0) {
					match->mem.base = (MODE == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				} else if(strncmp(between, "reg", 3) == 0) {
					//setup memory base using known_val
					Val tmp_val;
					get_value(known_val, between, &tmp_val);
					match->mem.base = tmp_val.reg;
				} else if(strncmp(between, "NONE", 4) == 0) {
					match->mem.base = X86_REG_INVALID;
				} else {
					//setup memory base
					match->mem.base = get_reg_from_name(handle, between);
				}
				//mark the base as enabled
				match->check_base = true;
			}
			match->mem_enabled = true;
			match->mem_known = true;
		} else if(strncmp(line, "<mem_index>", 11) == 0) {
			//extract string between <mem_index>string</mem_index>
			between = str_between(line, "<mem_index>", "</mem_index>");
			//check if the stack register is used
			if(between[0] == '?') {
				match->mem.index = X86_REG_INVALID;
				match->check_index = false;
			} else {
				if(strncmp(between, "stack", 5) == 0) {
					match->mem.index = (MODE == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				} else if(strncmp(between, "reg", 3) == 0) {
					//setup memory index
					Val tmp_val;
					get_value(known_val, between, &tmp_val);
					match->mem.index = tmp_val.reg;
				} else if(strncmp(between, "NONE", 4) == 0) {
					match->mem.index = X86_REG_INVALID;
				} else {
					//setup memory index
					match->mem.index = get_reg_from_name(handle, between);
				}
				match->check_index = true;
			}
			//mark the index as enabled
			match->mem_enabled = true;
			match->mem_known = true;
		} else if(strncmp(line, "<mem_scale>", 11) == 0) {
			//extract string between <mem_scale>string</mem_scale>
			between = str_between(line, "<mem_scale>", "</mem_scale>");
			//setup memory scale
			if(between[0] == '?') {
				match->mem.scale = 0;
				match->check_scale = false;
			} else {
				match->mem.scale = atoi(between);
				match->check_scale = true;
			}
			//mark the scale as enabled
			match->mem_enabled = true;
			match->mem_known = true;
		} else if(strncmp(line, "<mem_disp>", 10) == 0) {
			//extract string between <mem_disp>string</mem_disp>
			between = str_between(line, "<mem_disp>", "</mem_disp>");
			//setup memory displacement
			if(between[0] == '?') {
				match->mem.disp = 0;
				match->check_disp = false;
			} else {
				match->mem.disp = atoi(between);
				match->check_disp = true;
			}
			//mark the displacement as enabled
			match->mem_enabled = true;
			match->mem_known = true;
		} else if(strncmp(line, "<mem_size_name>", 15) == 0) {
			//extract string between <mem_size_name>string</mem_size_name>
			between = str_between(line, "<mem_size_name>", "</mem_size_name>");
			//allocate space for memory size name
			match->mem_sz_str = calloc(strlen(between) + 1, sizeof(char));
			//setup memory size name
			memcpy(match->mem_sz_str, between, strlen(between));
		} else if(strncmp(line, "<mem_disp_off>", 14) == 0) {
			//extract string between <mem_disp_off>string</mem_disp_off>
			between = str_between(line, "<mem_disp_off>", "</mem_disp_off>");
			//memorize the offset
			match->mem_disp_off = atoi(between);
			//notify we set it
			match->mem_disp_off_enabled = true;
		} else if(strncmp(line, "<mem_enable_checks>", 19) == 0) {
			match->check_size = true;
			match->check_base = true;
			match->check_disp = true;
			match->check_index = true;
			match->check_scale = true;
		}
		//increment read to exclude '\n'
		tot_read += (read + 1);
	}
	//something went wrong if you reach this statement, return NULL
	return match;
}

//peephole match functions
static bool check_match(csh handle, Instruction *insn, ConcurrentMatch *concurrent_match, uint8_t mode) {
	PeepMatch *match = concurrent_match->match;
	List *known_val = concurrent_match->known_val;
	//check if the instruction reads from an already read memory location, if true, abort this peephole
	MemoryLocation mem = { 0 };
	if(get_src_mem(insn, &mem)) {
		ListEntry *mem_val = known_val->first;
		ValCouple *couple;
		while(mem_val) {
			couple = (ValCouple *)mem_val->content;
			if(couple->name[0] == 'a') {
				//we are reading from a previously used MemoryLocation
				if(memcmp(&mem, &couple->val.mem, sizeof(MemoryLocation)) == 0) {
					concurrent_match->invalid = true;
				}
			}
			mem_val = mem_val->next;
		}
	}
	//check if we need to abort this peephole because the registers (src_reg/dst_reg/base/index) are modified
	//WARNING: it would be useful to implement a check to know if the memory location is overwritten using different base/index
	cs_x86 *x86 = &(insn->insn->detail->x86); cs_x86_op *op; size_t op_count = x86->op_count; uint8_t reg;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		//we need to check if a register is read/modified by the instruction in an explicit way
		if(op->type == X86_OP_REG && check_access(concurrent_match->known_val, op->reg, op->access)) concurrent_match->invalid = true;
		//check if this instruction is writing 
		if(op->type == X86_OP_MEM && (op->access == CS_AC_WRITE || op->access == (CS_AC_READ|CS_AC_WRITE))) {
			//WARNING: this is a stupid check AND MUST BE IMPROVED
			if(is_same_register_type(op->mem.base, X86_REG_RSP) && check_access(concurrent_match->known_val, op->mem.base, CS_AC_READ)) concurrent_match->invalid = true;
		}
	}
	//we are also going to check if a register is read/write in an implicit way
	size_t regs_write = insn->insn->detail->regs_write_count;
	for(size_t i = 0; i < regs_write; i++) {
		reg = insn->insn->detail->regs_write[i];
		if(check_access(concurrent_match->known_val, reg, CS_AC_WRITE)) concurrent_match->invalid = true;
	}
	size_t regs_read = insn->insn->detail->regs_read_count;
	for(size_t i = 0; i < regs_read; i++) {
		reg = insn->insn->detail->regs_read[i];
		if(check_access(concurrent_match->known_val, reg, CS_AC_READ)) concurrent_match->invalid = true;
	}
	//check if the mnemonic is the same (if a mnemonic is expected)
	bool mnemonic_match = false, op1_match = true, op2_match = true;
	uint8_t second_reg = X86_REG_INVALID, first_reg = X86_REG_INVALID, size = 0;
	if(match->check_mnemonic) {
		ListEntry *next_ins_name = match->insn_list->first;
		while(!mnemonic_match && next_ins_name) {
			if(cmp_mnemonic(insn->insn->mnemonic, (char *)next_ins_name->content)) mnemonic_match = true;
			next_ins_name = next_ins_name->next;
		}
	} else {
		mnemonic_match = true;
	}
	if(mnemonic_match) {
		//check if the destination and source registers are matched
		if(match->first_reg_enabled) {
			if(get_dst_reg(insn, &reg, &size, CS_AC_WRITE) || get_dst_reg(insn, &reg, &size, CS_AC_WRITE|CS_AC_READ)) {
				first_reg = reg;
				if(match->check_first_reg_size && match->first_reg_sz != size) op1_match = false;
				if(is_valid(match->first_reg) && match->first_reg != reg) op1_match = false;
				//check excluded registers
				if(match->no_first_reg) {
					char *no_reg_str;
					ListEntry *no_reg_e = match->no_first_reg->first;
					while(no_reg_e) {
						//extract register
						no_reg_str = (char *)no_reg_e->content;
						//check if 'dst_reg' is in the excluded list
						if(strncmp(no_reg_str, "reg", 3) == 0) {
							Val reg_val;
							if(get_value(known_val, no_reg_str, &reg_val) && is_same_register_type(reg_val.reg, first_reg)) op1_match = false;
						} else {
							uint8_t reg_val = get_reg_from_name(handle, no_reg_str);
							if(is_same_register_type(reg_val, first_reg)) op1_match = false; 
						}
						//check next excluded register
						no_reg_e = no_reg_e->next;
					}
				}
			} else {
				//impossible to extract the destination register, match failed
				op1_match = false;
			}
		}
		if(match->second_reg_enabled) {
			if(get_src_reg(insn, &reg, &size) || (reg = get_reg_at(insn, REG_SECOND, &size))) {
				second_reg = reg;
				if(match->check_second_reg_size && match->second_reg_sz != size) op2_match = false;
				if(is_valid(match->second_reg) && match->second_reg != reg) op2_match = false;
				if(match->first_reg_enabled) {
					if(match->second_reg_name != NULL && match->first_reg_name != NULL && strcmp(match->second_reg_name, match->first_reg_name) == 0) {
						if(second_reg != first_reg) op2_match = false;
					}
				}
				//check excluded registers
				if(match->no_second_reg) {
					char *no_reg_str;
					ListEntry *no_reg_e = match->no_second_reg->first;
					while(no_reg_e) {
						//extract register
						no_reg_str = (char *)no_reg_e->content;
						//check if 'dst_reg' is in the excluded list
						if(strncmp(no_reg_str, "reg", 3) == 0) {
							Val reg_val;
							if(get_value(known_val, no_reg_str, &reg_val) && is_same_register_type(reg_val.reg, second_reg)) op2_match = false;
						} else {
							uint8_t reg_val = get_reg_from_name(handle, no_reg_str);
							if(is_same_register_type(reg_val, second_reg)) op2_match = false; 
						}
						//check next excluded register
						no_reg_e = no_reg_e->next;
					}
				}
			} else {
				//impossible to extract the source register, match failed
				op2_match = false;
			}
		}
		//check if the memory is matched
		if(match->mem_enabled) {
			if(get_mem(insn, &mem)) {
				MemoryLocation tmp_mem = { .seg = 0, .size = mem.size, .base = mem.base, .index = mem.index, .scale = mem.scale, .disp = mem.disp, .off = 0 };
				//ignore segment register (always for now)
				mem.seg = 0; match->mem.seg = 0;
				//check if we need to compare the size/displacement/scale
				if(!match->check_size) mem.size = 0;
				if(!match->check_base) mem.base = 0;
				if(!match->check_disp) mem.disp = 0;
				if(!match->check_index) mem.index = 0;
				if(!match->check_scale) mem.scale = 0;
				//compare the two memory locations
				if(match->mem_known && memcmp(&mem, &(match->mem), sizeof(MemoryLocation)) != 0) op1_match = false;
				//reset to original values
				mem.size = tmp_mem.size;
				mem.base = tmp_mem.base;
				mem.disp = tmp_mem.disp;
				mem.index = tmp_mem.index;
				mem.scale = tmp_mem.scale;
			} else {
				//the memory location is non_existent, math failed
				op1_match = false;
			}
		}
		//check if the immediate is matched
		uint64_t imm; uint8_t size;
		if(match->imm_enabled) {
			if(get_imm(insn, &imm, &size)) {
				if(match->imm_known && match->imm != imm) op1_match = false;
				if(match->check_imm_size && match->imm_sz != size) op1_match = false;
			} else {
				//the immediate is non existent, match failed
				op1_match = false;
			}
		}
		//check if the match is complete
		if(mnemonic_match && op1_match && op2_match) {
			bool add_warning = false; uint8_t warning_reg_1 = X86_REG_INVALID, warning_reg_2 = X86_REG_INVALID, warning_reg_rsp = X86_REG_INVALID;
			//add the mnemonic name to 'known_val'
			if(match->insn_name) {
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				couple->name = calloc(strlen(match->insn_name) + 1, sizeof(char));
				couple->val.op = calloc(strlen(insn->insn->mnemonic) + 1, sizeof(char));
				memcpy(couple->name, match->insn_name, strlen(match->insn_name));
				memcpy(couple->val.op, insn->insn->mnemonic, strlen(insn->insn->mnemonic));
				ListPush(known_val, ListEntryCreate(couple));
			}
			//update the known values list (with first reg value)
			if(match->first_reg_enabled && !is_valid(match->first_reg)) {
				//the value is not known, so now we can add it to the list
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				couple->name = calloc(strlen(match->first_reg_name) + 1, sizeof(char));
				memcpy(couple->name, match->first_reg_name, strlen(match->first_reg_name));
				couple->val.reg = first_reg;
				entry->content = couple;
				ListPush(known_val, entry);
			} else if(match->first_reg_enabled) {
				warning_reg_1 = match->first_reg;
				add_warning = true;
			}
			//update the known values list (with second reg value)
			if(match->second_reg_enabled && !is_valid(match->second_reg)) {
				//the value is not known, so now we can add it to the list
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				couple->name = calloc(strlen(match->second_reg_name) + 1, sizeof(char));
				memcpy(couple->name, match->second_reg_name, strlen(match->second_reg_name));
				couple->val.reg = second_reg;
				entry->content = couple;
				ListPush(known_val, entry);
			} else if(match->second_reg_enabled) {
				warning_reg_2 = match->second_reg;
				add_warning = true;
			}
			//update the known values list (with imm value)
			if(match->imm_enabled && !match->imm_known) {
				//update the immediate value if 'update_mem_str' is enabled
				if(match->update_imm_str) {
					uint64_t op1, op2;
					//parse the string represented as: reverse-polish-notation
					if(match->update_imm_str[2] == 'I') {
						op1 = imm;
						op2 = atoi((char *)(match->update_imm_str + 4));
					} else {
						match->update_imm_str[3] = '\0';
						op1 = atoi((char *)(match->update_imm_str + 2));
						op2 = imm;
					}
					//execute the operation
					switch(match->update_imm_str[0]) {
						case '+':
							imm = op1 + op2;
							break;
						case '-':
							imm = op1 - op2;
							break;
						case '^':
							imm = (uint64_t)pow(op1, op2);
							break;
					}
				}
				//the value is not known, so now we can add it to the list
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				couple->name = calloc(strlen(match->imm_name) + 1, sizeof(char));
				memcpy(couple->name, match->imm_name, strlen(match->imm_name));
				couple->val.imm = imm;
				entry->content = couple;
				ListPush(known_val, entry);
			}
			//update the known values list (with mem value)
			if(match->mem_enabled && !match->mem_known) {
				//the value is not known, so now we can add it to the list
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				couple->name = calloc(strlen(match->mem_name) + 1, sizeof(char));
				memcpy(couple->name, match->mem_name, strlen(match->mem_name));
				couple->val.mem.seg = mem.seg;
				couple->val.mem.size = mem.size;
				couple->val.mem.base = mem.base;
				couple->val.mem.index = mem.index;
				couple->val.mem.scale = mem.scale;
				couple->val.mem.disp = mem.disp;
				//setup the memory offset if present
				if(match->mem_disp_off && is_same_register_type(mem.base, X86_REG_RSP)) {
					couple->val.mem.off = match->mem_disp_off;
				}
				entry->content = couple;
				ListPush(known_val, entry);
			}
			//update the known values list (with mem size value)
			if(match->mem_sz_str && get_mem(insn, &mem)) {
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				couple->name = calloc(strlen(match->mem_sz_str) + 1, sizeof(char));
				memcpy(couple->name, match->mem_sz_str, strlen(match->mem_sz_str));
				couple->val.imm = mem.size;
				ListPush(known_val, ListEntryCreate(couple));
			}
			//check if the instruction uses the stack (it is PUSH or POP), if TRUE add 'esp' to 'known_val'
			if(cmp_mnemonic((char *)(match->insn_list->first->content), "push") || cmp_mnemonic((char *)(match->insn_list->first->content), "pop")) {
				warning_reg_rsp = X86_REG_RSP;
				add_warning = true;
			}
			//check if the instruction reads from the stack, if TRUE add 'esp' to 'known_val'
			if(is_memory_insn(insn) && is_same_register_type(get_base(insn), X86_REG_RSP)) {
				warning_reg_rsp = X86_REG_RSP;
				add_warning = true;
			}
			//add 'rsp' to 'known_val' as 'warning'
			if(add_warning && is_valid(warning_reg_1)) {
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				char *name = "warning";
				couple->name = calloc(strlen(name), sizeof(char));
				memcpy(couple->name, name, strlen(name));
				couple->val.reg = warning_reg_1;
				entry->content = couple;
				ListPush(known_val, entry);
			}
			if(add_warning && is_valid(warning_reg_2)) {
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				char *name = "warning";
				couple->name = calloc(strlen(name), sizeof(char));
				memcpy(couple->name, name, strlen(name));
				couple->val.reg = warning_reg_2;
				entry->content = couple;
				ListPush(known_val, entry);
			}
			if(add_warning && is_valid(warning_reg_rsp)) {
				//adding a warning for ESP/RSP
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				char *name = "warning";
				couple->name = calloc(strlen(name), sizeof(char));
				memcpy(couple->name, name, strlen(name));
				couple->val.reg = warning_reg_rsp;
				entry->content = couple;
				ListPush(known_val, entry);
				//adding the accessed memory location: ss:[esp] or ss:[rsp]
				mem.base = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				mem.index = X86_REG_INVALID;
				mem.scale = 1;
				mem.disp = 0;
				mem.size = (mode == CS_MODE_32) ? 4 : 8;
				entry = calloc(1, sizeof(ListEntry));
				couple = calloc(1, sizeof(ValCouple));
				name = "attention";
				couple->name = calloc(strlen(name), sizeof(char));
				memcpy(couple->name, name, strlen(name));
				memcpy(&couple->val.mem, &mem, sizeof(MemoryLocation));
				entry->content = couple;
				ListPush(known_val, entry);
			}
			//check if the instruction reads from a memory location, if TRUE add it to 'known_val'
			if(get_src_mem(insn, &mem)) {
				ListEntry *entry = calloc(1, sizeof(ListEntry));
				ValCouple *couple = calloc(1, sizeof(ValCouple));
				char *name = "attention";
				couple->name = calloc(strlen(name), sizeof(char));
				memcpy(couple->name, name, strlen(name));
				memcpy(&couple->val.mem, &mem, sizeof(MemoryLocation));
				entry->content = couple;
				ListPush(known_val, entry);
			}
			concurrent_match->invalid = false;
			return true;
		}
	}
	return false;
}

static ListEntry *replace_match(csh handle, List *list, ConcurrentMatch *concurrent_match, uint8_t mode) {
	if(VERBOSE) printf("\n[+] Found full match!\n");
	//debug: print the matched sequence
	ListEntry *remove_ins, *matched_ins = concurrent_match->ins_list->first;
	ListEntry *last_ins = (ListEntry *)((ListEntry *)concurrent_match->ins_list->last)->content;
	last_ins = last_ins->next;
	while(matched_ins) {
		remove_ins = (ListEntry *)matched_ins->content;
		if(VERBOSE) print_insn("\t", (Instruction *)remove_ins->content);
		matched_ins = matched_ins->next;
	}
	ListEntry *first_ins = NULL;
	if(concurrent_match->rep_list) {
		//debug: print replacement sequence
		if(VERBOSE) printf("[+] Replacement instructions:\n");
		ListEntry *replacement_ins = concurrent_match->rep_list->first, *tag;
		first_ins = (ListEntry *)(concurrent_match->ins_list->last->content);
		ValCouple *couple;
		char *replaced_ins, *mem_indicator, mem[60], imm[20];
		while(replacement_ins) {
			replaced_ins = (char *)replacement_ins->content;
			tag = concurrent_match->known_val->first;
			while(tag) {
				couple = (ValCouple *)tag->content;
				switch(couple->name[0]) {
					case 's':
						replaced_ins = str_replace(replaced_ins, couple->name, get_mem_indicator(couple->val.imm), -1);
						break;
					case 'o':
						replaced_ins = str_replace(replaced_ins, couple->name, couple->val.op, -1);
						break;
					case 'r':
						//printf("Name: %s, Reg: %s\n", couple->name, (char *)cs_reg_name(handle, couple->val.reg));
						replaced_ins = str_replace(replaced_ins, couple->name, (char *)cs_reg_name(handle, couple->val.reg), -1);
						break;
					case 'm':
						//we give the user the possibility to adjust a memory displacement
						if(couple->val.mem.off) {
							couple->val.mem.disp += couple->val.mem.off;
						}
						//print the memory location
						mem_indicator = get_mem_indicator(couple->val.mem.size);
						sprintf(mem, "%s ptr [%s]", mem_indicator, fix_mem_op_str(handle, couple->val.mem.base, couple->val.mem.index, couple->val.mem.scale, couple->val.mem.disp));
						replaced_ins = str_replace(replaced_ins, couple->name, mem, -1);
						break;
					case 'i':
						sprintf(imm, "0x%lx", couple->val.imm);
						replaced_ins = str_replace(replaced_ins, couple->name, imm, -1);
						break;
				}
				tag = tag->next;
			}
			//debug
			//printf("\t%s\n", replaced_ins);
			//insert the updated instruction on the Assembly listing
			Instruction *new_curr_ins = calloc(1, sizeof(Instruction));
			new_curr_ins->insn = calloc(1, sizeof(cs_insn));
			char *space = strstr(replaced_ins, " ");
			memcpy(new_curr_ins->insn->mnemonic, replaced_ins, space - replaced_ins);
			space++;
			memcpy(new_curr_ins->insn->op_str, space, strlen(space));
			if(!(reassemble(new_curr_ins, mode) && update_disasm(new_curr_ins, TEXT_ADDRESS, mode))) {
				if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
			} else {
				if(VERBOSE) print_insn("\t", new_curr_ins);
				ListEntry *new_ins = ListEntryCreate(new_curr_ins);
				//print_insn("Attaching after: ", (Instruction *)first_ins->content);
				ListInsertAfter(list, first_ins, new_ins);
				first_ins = new_ins;
			}
			//go to the next replacement instruction
			replacement_ins = replacement_ins->next;
		}
	}
	last_ins = (first_ins) ? first_ins->next : NULL;
	//delete old instructions
	first_ins = concurrent_match->ins_list->first;
	while(first_ins) {
		remove_ins = (ListEntry *)first_ins->content;
		//print_insn("Removing: ", (Instruction *)remove_ins->content);
		if(NO_NOP) {
			ListRemove(list, remove_ins);
		} else {
			RemoveWithNop(list, remove_ins, mode);
		}
		first_ins = first_ins->next;
	}
	return last_ins;
}

/*
	Name: peephole_optimize
	Description: this function will apply a peephole optimization matching the patterns
	like Flex, the lexical analyzer: all the patterns are tested in parallel.
*/
bool peephole_optimize(csh handle, List *list, List *patterns, uint8_t mode, Registers *start_regs, Registers *end_regs, List *mem_writes) {
	bool optimized = false;
	//check if instructions list and patterns are available
	if(!list || !list->first) return optimized;
	if(!patterns || !patterns->first) return optimized;
	//declare useful variables
	ListEntry *current = NULL, *cm_entry = NULL, *pattern_start_ins = NULL, *next_ins = NULL;
	List *concurrent_list = ListCreate();
	ConcurrentMatch *last_full_match = NULL;
	ConcurrentMatch *concurrent_match = NULL;
	//apply an iterative pattern match until there are no more match to apply
	bool matched, init_match = true;
	size_t cm_counter;
	do {
		//reset flags
		matched = false;
		//start the match from the first instruction in the Assembly listing
		current = list->first;
		//check all the instructions
		while(current) {
			//debug string
			if(VERBOSE) print_insn("[!] Matching: ", (Instruction *)current->content);
			//create current patterns state
			if(init_match) {
				//save the first instruction
				pattern_start_ins = current;
				//reset 'cm_counter'
				cm_counter = 0;
				//initialize the list of ConcurrentMatch
				ListEntry *curr_pat, *pat_list_e, *cm_e;
				ConcurrentMatch *conc_match;
				PeepPattern *curr_peep;
				List *pat_list;
				char *pat_str;
				if(!concurrent_list->first) {
					//printf("FIRST INITIALIZATION\n");
					//this is the first initialization
					curr_pat = patterns->first;
					while(curr_pat) {
						//increment the 'cm_counter' for each ConcurrentMatch
						cm_counter++;
						//extract current PeepPattern
						curr_peep = (PeepPattern *)curr_pat->content;
						//extract the first match string for this PeepPattern
						pat_list = curr_peep->pat_list;
						pat_list_e = pat_list->first;
						pat_str = (char *)pat_list_e->content;
						//creating the PeepMatch
						conc_match = calloc(1, sizeof(ConcurrentMatch));
						conc_match->known_val = ListCreate();
						conc_match->ins_list = ListCreate();
						conc_match->match = create_insn_match(handle, pat_str, conc_match->known_val, mode);
						conc_match->next_match = pat_list_e->next;
						conc_match->rep_list = curr_peep->rep_list;
						conc_match->match_count = 0;
						//adding ConcurrentMatch to 'concurrent_list'
						cm_e = calloc(1, sizeof(ListEntry));
						cm_e->content = conc_match;
						ListPush(concurrent_list, cm_e);
						//go to the next PeepPattern
						curr_pat = curr_pat->next;
					}
				} else {
					//printf("NOT FIRST INITIALIZATION\n");
					//this is not the first initialization, reinitialize 'concurrent_list' entries
					cm_e = concurrent_list->first;
					conc_match = (ConcurrentMatch *)cm_e->content;
					curr_pat = patterns->first;
					while(curr_pat) {
						//increment 'cm_counter' for each ConcurrentMatch
						cm_counter++;
						//extract current PeepPattern
						curr_peep = (PeepPattern *)curr_pat->content;
						//extract the first match string for this PeepPattern
						pat_list = curr_peep->pat_list;
						pat_list_e = pat_list->first;
						pat_str = (char *)pat_list_e->content;
						//creating the PeepMatch
						conc_match = (ConcurrentMatch *)cm_e->content;
						//free old 'PeepMatch' and 'known_val'
						free(conc_match->match);
						ListDestroy(conc_match->known_val);
						//ListDestroy(conc_match->ins_list);
						//update the values
						conc_match->known_val = ListCreate();
						conc_match->ins_list = ListCreate();
						conc_match->match = create_insn_match(handle, pat_str, conc_match->known_val, mode);
						conc_match->next_match = pat_list_e->next;
						conc_match->invalid = false;
						conc_match->advance = false;
						conc_match->match_count = 0;
						//change list entry
						cm_e->content = conc_match;
						//go to the next PeepPattern
						curr_pat = curr_pat->next;
						//go to the next ListEntry
						cm_e = cm_e->next;
					}
				}
				//we just initialized 'concurrent_list', notify it
				init_match = false;
			} else {
				//printf("ADVANCE\n");
				//advance the list of ConcurrentMatch, ignoring invalid ones
				ListEntry *cm_e = concurrent_list->first;
				ConcurrentMatch *conc_match;
				while(cm_e) {
					//extract ConcurrentMatch
					conc_match = (ConcurrentMatch *)cm_e->content;
					//check if the ConcurrentMatch is NOT invalid, then update it
					if(!conc_match->invalid && conc_match->advance) {
						//TRYING TO FIX
						//check if we can advance with the sequence
						if(conc_match->next_match) {
							//create the next PeepMatch
							free(conc_match->match);
							conc_match->match = create_insn_match(handle, (char *)conc_match->next_match->content, conc_match->known_val, mode);
							conc_match->next_match = conc_match->next_match->next;
							conc_match->advance = false;
						}
						//TRYING TO FIX
					}
					//go to the next ConcurrentMatch
					cm_e = cm_e->next;
				}
			}
			//test each pattern with the current instruction
			//Instruction *insn = (Instruction *)current->content;
			cm_entry = concurrent_list->first;
			//debug
			//if(VERBOSE) print_insn("Pattern start instruction: ", pattern_start_ins->content);
			while(cm_entry) {
				//extract ConcurrentMatch
				concurrent_match = (ConcurrentMatch *)cm_entry->content;
				//check match with the current instruction, only if valid
				if(!concurrent_match->invalid) {
					//check_match already updated 'conc_match->invalid' if the match is invalid
					if(check_match(handle, (Instruction *)current->content, concurrent_match, mode)) {
						//matched an instruction, debug
						//pattern matched, increment the matches count
						concurrent_match->match_count++;
						//pattern matched, notify we need to advance it
						concurrent_match->advance = true;
						//we matched a pattern in a sequence, save the instruction
						ListEntry *matched_ins = calloc(1, sizeof(ListEntry));
						matched_ins->content = current;
						ListPush(concurrent_match->ins_list, matched_ins);
						//the pattern is matched, control if we reached the end of the sequence
						if(!concurrent_match->next_match) {
							//this sequence is ended, mark it as the last full match
							last_full_match = concurrent_match;
							//control if there are no other sequences still alive
							if(num_sequence_alive(concurrent_list, pattern_start_ins) == 1) {
								//in this case, replace the match
								next_ins = replace_match(handle, list, last_full_match, mode);
								//notify we matched at least a sequence, so we can do another round
								matched = true; optimized = true; init_match = true;
							}
							//mark the sequence as ended ---> TEST
							concurrent_match->invalid = true;
						}
					} else if(SEQUENTIAL_SEARCH) {
						concurrent_match->invalid = true;
					}
					//check if the pattern is invalidated and decrement the counter
					if(concurrent_match->invalid) cm_counter--;
				}
				//check if we matched a full sequence
				if(init_match) break;
				//go to the next ConcurrentMatch
				cm_entry = cm_entry->next;
			}
			//check if the remaining patterns matched at least an instruction
			ListEntry *test = concurrent_list->first;
			ConcurrentMatch *test1;
			bool no_match = true;
			uint32_t test2 = 1;
			while(!last_full_match && test) {
				test1 = (ConcurrentMatch *)test->content;
				if(!test1->invalid) {
					if(test1->match_count > 0) {
						no_match = false;
						test2++;
					} else {
						test1->invalid = true;
					}
				}
				test = test->next;
			}
			//check if we matched something, continue after it
			if(init_match) {
				current = next_ins;
				next_ins = NULL;
				last_full_match = NULL;
				continue;
			}
			if(no_match) {
				//reinitialize the patterns and start again from this instruction
				init_match = true;
				//advance one instruction
				if(current != pattern_start_ins && !last_full_match) {
					current = pattern_start_ins->next;
					continue;
				} else if(last_full_match) {
					//we matched something, replace the last instruction
					ListEntry *start_here = replace_match(handle, list, last_full_match, mode);
					//notify we matched at least a sequence, so we can do another round
					matched = true; optimized = true;
					//reset 'last_full_match'
					last_full_match = NULL;
					//restart the search right after this replacement
					current = start_here;
					//print_insn("start again from:", current->content);
					continue;
				}
			}
			//check if all ConcurrentMatch are invalid, if true, reinitialize them
			if(cm_counter == 0) {
				//reinitialize & continue
				init_match = true;
			}
			//check if there is an active pattern and we reached the end
			if(!no_match && !current->next) {
				//one or more match didn't complete, start from pattern_start_ins->next
				pattern_start_ins = pattern_start_ins->next;
				//reinitialize patterns
				init_match = true;
				//reset 'current'
				current = pattern_start_ins;
				continue;
			}
			//check the next instruction
			current = current->next;
		}
	} while(matched);
	//return the optimization status
	return optimized;
}