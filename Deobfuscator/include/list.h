#include <structures.h>

char *get_eflag_name(uint64_t flag);

/* Double Linked List Definition */

typedef struct ListEntry {
	struct ListEntry *next;
	struct ListEntry *prev;
	void *content;
} ListEntry;

typedef struct List {
	uint32_t entry_count;
	ListEntry *first;
	ListEntry *last;
} List;

/* Double Linked List Implementation */

ListEntry *ListEntryCreate(void *content) {
	//remember to free it when unused
	ListEntry *new_entry = calloc(1, sizeof(ListEntry));
	new_entry->content = content;
	return new_entry;
}

List *ListCreate() {
	//remember to free it when unused
	return calloc(1, sizeof(List));
}

void ListDestroy(List *list) {
	ListEntry *current = list->first;
	while(current != NULL) {
		free(current->content);
		current = current->next;
	}
	//free(current);
	//free(list->first);
    //free(list->last);
    //free(list);
}

void ListInsertAfter(List *list, ListEntry *old_entry, ListEntry *new_entry) {
	if(!new_entry) return;
	if(old_entry) {
		//Next old entry update
		ListEntry *next = old_entry->next;
		if(next != NULL) {
			next->prev = new_entry;
		}
		//Update new_entry prev & next
		new_entry->prev = old_entry;
		new_entry->next = next;
		//Update old_entry next
		old_entry->next = new_entry;
		if(list->last == old_entry) {
			list->last = new_entry;
		}
		//increment List size
		list->entry_count++;
	}
}

void ListInsertBefore(List *list, ListEntry *old_entry, ListEntry *new_entry) {
	if(old_entry) {
		//Next old instruction update
		ListEntry *prev = old_entry->prev;
		if(prev) prev->next = new_entry;
		//Update new_entry prev & next
		new_entry->prev = prev;
		new_entry->next = old_entry;
		//Update old_entry next
		old_entry->prev = new_entry;
		if(list->first == old_entry) {
			list->first = new_entry;
		}
		//increment List size
		list->entry_count++;
	}
}

void ListPush(List *list, ListEntry *new_entry) {
	if(!(list->last)) {
		list->first = new_entry;
		list->last = new_entry;
	} else {
		list->last->next = new_entry;
		new_entry->prev = list->last;
		list->last = new_entry;
	}
	//increment List size
	list->entry_count++;
}

bool ListEntrySetNext(ListEntry *current, ListEntry *next) {
	if(!current) return false;
	current->next = next;
	return true;
}

bool ListEntrySetPrev(ListEntry *current, ListEntry *prev) {
	if(!current) return false;
	current->prev = prev;
	return true;
}

void ListRemove(List *list, ListEntry *old_entry) {
	if(!old_entry) return;
	if(list->first == old_entry) {
		list->first = old_entry->next;
	}
	if(list->last == old_entry) {
		list->last = old_entry->prev;
	}
	if(old_entry->prev) {
		old_entry->prev->next = old_entry->next;
	}
	if(old_entry->next) {
		old_entry->next->prev = old_entry->prev;
	}
	//free(old_entry);
}

void *ListPop(List *list) {
	if(!list) return NULL;
	if(list->entry_count == 0) return NULL;
	//remember to free the popped_entry somewhere
	void *popped_entry = list->first;
	ListRemove(list, popped_entry);
	//decrement list size
	list->entry_count--;
	return popped_entry;
}

bool ListCmpEntries(ListEntry *e1, ListEntry *e2, size_t n) {
	return (memcmp(e1->content, e2->content, n) == 0) ? true : false;
}

/* Information functions */

uint32_t ListNumEntry(List *list) {
	return list->entry_count;
}

bool ListIsEmpty(List *list) {
	return (bool)list->entry_count;
}

ListEntry *ListIsBefore(ListEntry *first, ListEntry *second) {
	if(!first && !second) return NULL;
	if(!first && second) return second;
	if(first && !second) return first;
	//check if "first" is encountered before "second"
	ListEntry *temp = first;
	while(temp) {
		if(temp == second) return first;
		temp = temp->next;
	}
	return second;
}

void ListChangeEntry(ListEntry *entry, void *new_content) {
	//delete old content
	free(entry->content);
	//assign new content
	entry->content = new_content;
}

/* Useful debug functions */

void print_disassembly(csh handle, List *list, bool advanced) {
	cs_x86 *x86;
	cs_x86_op *op;
	size_t op_count = 0;
	ListEntry *entry = list->first;
	Instruction *current;
	while(entry) {
		//extract Instruction from the current ListEntry
		current = (Instruction *)entry->content;
		if(!SHOW_NOP && strncmp(current->insn->mnemonic, "nop", 3) == 0) {
			entry = entry->next;
			continue;
		}
		if(advanced) {
			printf("0x%lx %s %s (invalid: %d)\n", current->insn->address, current->insn->mnemonic, current->insn->op_str, current->invalid);
		} else {
			if(SHOW_ADDR) {
				printf("0x%lx %s %s\n", current->insn->address, current->insn->mnemonic, current->insn->op_str);
			} else {
				printf("%s %s\n", current->insn->mnemonic, current->insn->op_str);
			}
		}
		if(advanced /*&& !current->invalid*/) {
			x86 = &(current->insn->detail->x86);
			op_count = x86->op_count;
			for(size_t i = 0; i < op_count; i++) {
				op = &(x86->operands[i]);
				switch(op->access) {
					case CS_AC_READ:
						printf("\t\tCS_AC_READ (%d)\n", op->access);
						break;
					case CS_AC_WRITE:
						printf("\t\tCS_AC_WRITE (%d)\n", op->access);
						break;
					case CS_AC_READ|CS_AC_WRITE:
						printf("\t\tCS_AC_READ|CS_AC_WRITE (%d)\n", op->access);
						break;
					default:
						printf("\t\tUNKNOWN (%d)\n", op->access);
						break;
				}
				switch((int)op->type) {
					case X86_OP_REG:
						printf("\t\toperands[%lx].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
						break;
					case X86_OP_IMM:
						printf("\t\toperands[%lx].type: IMM = 0x%lx\n", i, op->imm);
						printf("\t\toperands[%lx].size: IMM.size = 0x%x\n", i, op->size);
						break;
					//REMOVED FROM CAPSTONE-NEXT
					/*case X86_OP_FP:
						printf("\t\toperands[%lx].type: FP = %f\n", i, op->fp);
						break;*/
					case X86_OP_MEM:
						printf("\t\toperands[%lx].type: MEM\n", i);
						if (op->mem.segment != X86_REG_INVALID)
							printf("\t\t\toperands[%lx].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
						if (op->mem.base != X86_REG_INVALID)
							printf("\t\t\toperands[%lx].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
						if (op->mem.index != X86_REG_INVALID)
							printf("\t\t\toperands[%lx].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
						if (op->mem.scale != 1)
							printf("\t\t\toperands[%lx].mem.scale: %x\n", i, op->mem.scale);
						if (op->mem.disp != 0)
							printf("\t\t\toperands[%lx].mem.disp: 0x%lx\n", i, op->mem.disp);
						break;
					default:
						break;
				}
			}
			if (x86->eflags) {
				printf("[EFLAGS]:");
				for(int i = 0; i <= 45; i++) if(x86->eflags & ((uint64_t)1 << i)) printf(" %s", get_eflag_name((uint64_t)1 << i));
				printf("\n");
			}
			if(current->insn->detail->regs_write_count > 0) {
				printf("[REG WRITE]: ");
				for(size_t i = 0; i < current->insn->detail->regs_write_count; i++) {
					printf("(%s)", cs_reg_name(handle, current->insn->detail->regs_write[i]));
				}
			}
			if(current->insn->detail->regs_read_count > 0) {
				printf("\n[REG READ]: ");
				for(size_t i = 0; i < current->insn->detail->regs_read_count; i++) {
					printf("(%s)", cs_reg_name(handle, current->insn->detail->regs_read[i]));
				}
			}
			printf("\n[HEX]: ");
			for(size_t i = 0; i < current->insn->size; i++) {
				printf("%02x ", current->insn->bytes[i]);
			}
			printf("\n");
		}
		entry = entry->next;
	}
}

void print_memory_value(List *list) {
	if(!list) return;
	MemoryValue *mem_val;
	ListEntry *entry = list->first;
	while(entry) {
		mem_val = (MemoryValue *)entry->content;
		printf("MemoryValue { address = 0x%lx, size = 0x%x, value = 0x%lx }\n", mem_val->address, mem_val->size, mem_val->value);
		entry = entry->next;
	}
}