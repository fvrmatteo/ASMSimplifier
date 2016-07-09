/* Importing XEDParseAssemble */

#ifdef __linux__
#include <dlfcn.h>
#include <keystone/keystone.h>
//#include <keystone_test.h>
#elif _WIN32
#include <XEDParse/XEDParse.h>
#else
#endif

#ifdef __linux__

/* Library pointers for dlopen */

	void *keystone_lib;
	
	ks_engine *ks = NULL;

	/* Function pointers for dlsym */

	int (*ks_asm_sym)(ks_engine *, const char *, uint64_t, unsigned char **, size_t *, size_t *);
	ks_err (*ks_option_sym)(ks_engine *, ks_opt_type, size_t);
	ks_err (*ks_open_sym)(ks_arch, int, ks_engine **);
	ks_err (*ks_close_sym)(ks_engine *);
	ks_err (*ks_errno_sym)(ks_engine *);
	void (*ks_free_sym)(void *);

#elif _WIN32
	typedef XEDPARSE_STATUS (WINAPI *XEDParseAssemble)(XEDPARSE *xed_parse);
	XEDParseAssemble assemble;
#else
#endif

bool load_keystone() {
	//loading library
	keystone_lib = dlopen("libkeystone.so.1", RTLD_NOW);
	if(!keystone_lib) {
		printf("[-] Error loading libkeystone.so.1\n");
		return false;
	} else {
		//loading symbols
		ks_asm_sym = dlsym(keystone_lib, "ks_asm");
		if(!ks_asm_sym) { printf("[-] Symbol 'ks_asm' not found.\n"); return false; }
		ks_option_sym = dlsym(keystone_lib, "ks_option");
		if(!ks_option_sym) { printf("[-] Symbol 'ks_option' not found.\n"); return false; }
		ks_open_sym = dlsym(keystone_lib, "ks_open");
		if(!ks_open_sym) { printf("[-] Symbol 'ks_open' not found.\n"); return false; }
		ks_close_sym = dlsym(keystone_lib, "ks_close");
		if(!ks_close_sym) { printf("[-] Symbol 'ks_close' not found.\n"); return false; }
		ks_errno_sym = dlsym(keystone_lib, "ks_errno");
		if(!ks_errno_sym) { printf("[-] Symbol 'ks_errno' not found.\n"); return false; }
		ks_free_sym = dlsym(keystone_lib, "ks_free");
		if(!ks_free_sym) { printf("[-] Symbol 'ks_free' not found.\n"); return false; }
	}
	return true;
}

void unload_keystone() {
	dlclose(keystone_lib);
}
