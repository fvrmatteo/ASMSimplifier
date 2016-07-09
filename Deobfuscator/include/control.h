/*
	Name: is_assemblable
	Description: this function will check if an instruction is assemblable, using the mnemonic as
	indicator. For now only the mnemonic & immediate are used.
*/
bool is_assemblable(uint32_t id, uint64_t imm, uint8_t mode) {
	switch(id) {
		case X86_INS_ADD: if(mode == CS_MODE_64 && (imm & 0xFFFFFFFF00000000) != 0) return false; break;
		case X86_INS_CMOVO: return false;
		case X86_INS_MOVSX: return false;
	}
	return true;
}