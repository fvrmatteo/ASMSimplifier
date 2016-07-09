.PHONY: clean All

All:
	@echo "----------Building project:[ Deobfuscator - Debug ]----------"
	@cd "Deobfuscator" && "$(MAKE)" -f  "Deobfuscator.mk"
clean:
	@echo "----------Cleaning project:[ Deobfuscator - Debug ]----------"
	@cd "Deobfuscator" && "$(MAKE)" -f  "Deobfuscator.mk" clean
