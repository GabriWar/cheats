#pragma once

#include "utils.h"

// Process selection
libmem::Pid process_select();

// Process actions
ProcessAction show_process_actions(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt);

// Memory address input
void enter_memory_address(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt); 