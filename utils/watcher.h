#pragma once

#include "utils.h"

// Memory watching functions
bool watch_memory_region(const libmem::Process& process, libmem::Address address, size_t size = 16); 