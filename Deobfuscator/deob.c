#include <tests.h>
#include <list.h>
#include <op_utility.h>
#include <insn_utility.h>
#include <deadcode.h>
#include <emulation.h>
#include <peephole.h>
#include <arithmetic.h>

//define the general list
static List *list = NULL;
static bool extra = false;

#define TEST_BUILD false

int test_main() {
	char *test = "mov rax, qword ptr ss:[rbx + rsi * 0x8 + 0x998877]";
	char address[10] = { 0 }; sprintf(address, "0x%x", 0x10000000);
	char *mem_loc_str = str_between(test, "[", "]");
	char *op_str = str_replace(test, mem_loc_str, address, -1);
	printf("new: %s\n", op_str);
	//exit from the test
#ifdef _WIN32
	ExitProcess(EXIT_SUCCESS);
#elif __linux__
	exit(-1);
#endif
}

int main(int argc, char **argv) {
	//Setting the extra extrarmation flag
	if(argc == 2) {
		extra = atoi(argv[1]);
	}
	srand(time(NULL));
	if(TEST_BUILD) test_main();
	//Importing XEDParseAssemble from the dynamic library
#ifdef __linux__
	//Loading the library, Linux style
	load_keystone();
#elif _WIN32
	//Loading the library, Windows style
	HANDLE XEDLib = LoadLibrary("XEDParse.dll");
	if(XEDLib == NULL) {
		printf("[-] Error: LoadLibrary - 0x%x\n", GetLastError());
		return EXIT_FAILURE;
	}
	assemble = (XEDParseAssemble)GetProcAddress(XEDLib, "XEDParseAssemble");
	if(assemble == NULL) {
		printf("[-] Error: GetProcAddress - 0x%x\n", GetLastError());
		return EXIT_FAILURE;
	}
#else
#endif
	// Optimizing for stack operations
	csh handle;
	cs_insn *insn;
	cs_err err;
	size_t count;
	err = cs_open(CS_ARCH_X86, MODE, &handle);
	if(err != CS_ERR_OK) {
		printf("[-] Error: cs_open.\n");
		return -1;
	}
	//I want all possible details
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, (const uint8_t *)CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	if(count > 0) {
		//create list
		list = ListCreate();
		//adding original instructions to list
		Instruction *current = NULL;
		ListEntry *entry = NULL;
		for(size_t i = 0; i < count; i++) {
			current = calloc(1, sizeof(Instruction));
			current->insn = (cs_insn *)calloc(1, sizeof(cs_insn));
			memcpy(current->insn, &insn[i], sizeof(cs_insn));
			entry = ListEntryCreate(current);
			ListPush(list, entry);
		}
		printf("[!] Original code\n\n");
		print_disassembly(handle, list, extra);
		//init a fake initial registers context that will be used across the execution
		Registers *start_regs;
		init_reg_context(&start_regs, STACK_ADDRESS, MODE);
		//emulate the obfuscated code and save the end registers context result
		Registers *end_regs = calloc(1, sizeof(Registers));
		List *mem_writes = ListCreate();
		emulate_context(handle, list, start_regs, end_regs, mem_writes, MODE);
		if(!ListIsEmpty(mem_writes)) {
			//printf("The following memory locations are WRITE\n");
			//print_memory_value(mem_writes);
		}
		//start main optimization loop
		bool optimized;
		//initialize Peephole patterns
		init_patterns();
		
		Registers *st_regs = calloc(1, sizeof(Registers));
		Registers *end_regs_new = calloc(1, sizeof(Registers));
		List *mem_writes_new = ListCreate();
		
		if(FIRST_PASS) {
			do {
				
				optimized = false;
				
				while(peephole_optimize(handle, list, patterns, MODE, start_regs, end_regs, mem_writes)) optimized = true;
				
				emulate_context(handle, list, start_regs, end_regs_new, mem_writes_new, MODE);
				if(check_context_integrity(end_regs, mem_writes, end_regs_new, mem_writes_new)) {
					printf("\n[OK] Integrity kept! :D\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
				} else {
					printf("\n[NO] Integrity destroyed! D:\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
					exit(1);
				}
				
				while(arithmetic_solver(handle, list, MODE)) optimized = true;
				
				emulate_context(handle, list, start_regs, end_regs_new, mem_writes_new, MODE);
				if(check_context_integrity(end_regs, mem_writes, end_regs_new, mem_writes_new)) {
					printf("\n[OK] Integrity kept! :D\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
				} else {
					printf("\n[NO] Integrity destroyed! D:\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
					exit(1);
				}
				
				memcpy(st_regs, start_regs, sizeof(Registers));
				emulate_code(handle, list->first, NULL, st_regs, NULL, NULL, MODE, true);
				
				emulate_context(handle, list, start_regs, end_regs_new, mem_writes_new, MODE);
				if(check_context_integrity(end_regs, mem_writes, end_regs_new, mem_writes_new)) {
					printf("\n[OK] Integrity kept! :D\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
				} else {
					printf("\n[NO] Integrity destroyed! D:\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
					exit(1);
				}
				
				while(collapse_add_sub_2(handle, list, MODE)) optimized = true;
				
				emulate_context(handle, list, start_regs, end_regs_new, mem_writes_new, MODE);
				if(check_context_integrity(end_regs, mem_writes, end_regs_new, mem_writes_new)) {
					printf("\n[OK] Integrity kept! :D\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
				} else {
					printf("\n[NO] Integrity destroyed! D:\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
					exit(1);
				}
				
				if(!optimized) while(dead_code_elimination(handle, list, MODE)) optimized = true;
				
				emulate_context(handle, list, start_regs, end_regs_new, mem_writes_new, MODE);
				if(check_context_integrity(end_regs, mem_writes, end_regs_new, mem_writes_new)) {
					printf("\n[OK] Integrity kept! :D\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
				} else {
					printf("\n[NO] Integrity destroyed! D:\n");
					printf("\n\n------------ Simplified ------------\n\n");
					print_disassembly(handle, list, extra);
					exit(1);
				}
				
			} while(optimized);
		}
		free(st_regs);
		//show code after main optimization loop
		printf("\n\n------------ Simplified ------------\n\n");
		print_disassembly(handle, list, extra);
		//emulate new context
		//Registers *end_regs_new = calloc(1, sizeof(Registers));
		//List *mem_writes_new = ListCreate();
		emulate_context(handle, list, start_regs, end_regs_new, mem_writes_new, MODE);
		if(check_context_integrity(end_regs, mem_writes, end_regs_new, mem_writes_new)) {
			printf("\n[OK] Integrity kept! :D\n");
		} else {
			printf("\n[NO] Integrity destroyed! D:\n");
		}
		//free memory
		ListDestroy(mem_writes);
		free(end_regs);
		free(start_regs);
		cs_free(insn, count);
	} else {
		printf("[-] Error: cs_disasm.\n");
	}
	cs_close(&handle);

#ifdef __linux__
	unload_keystone();
#endif
	
	return 0;
}
