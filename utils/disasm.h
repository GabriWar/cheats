#pragma once

#include "utils.h"

// Disassembly
bool disassemble_memory_region(const libmem::Process& process, libmem::Address address, int instruction_count = 10); 