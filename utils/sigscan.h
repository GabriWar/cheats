#pragma once

#include "utils.h"

// Signature scanning
void scan_for_bytes(const libmem::Process& process, const std::optional<libmem::Module>& module);

// Find bytes utility
void find_bytes(const libmem::Process& process, const std::optional<libmem::Module>& module); 