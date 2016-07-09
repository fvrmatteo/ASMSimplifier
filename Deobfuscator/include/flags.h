//Display flags
#define INFO true
#define SHOW_NOP false
#define SHOW_ADDR false
#define VERBOSE true
#define VERBOSE_ERROR true
#define ENABLE_TEST_FUNCTIONS true

//Emulation testing values
#define TEXT_ADDRESS 0x501000
#define STACK_ADDRESS 0x1000
#define EMU_SIZE  2 * 1024 * 1024

//Optimizations flags
#define NO_NOP true
#define FIRST_PASS true
#define SEQUENTIAL_SEARCH true

//junk elimination
#define REMOVE_FLAG_INS true
#define REMOVE_UNUSED false

//Stack expansion
#define STACK_DISPLACEMENT 0x400

//Registers structure
#define REGISTERS_SIZE sizeof(Registers)/sizeof(uint64_t)
