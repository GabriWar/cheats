#pragma once

#include "utils.h"

// Module selection
ModuleSelectionResult show_process_modules(libmem::Pid process_pid);

// Module handling
void handle_module_menu(const libmem::Process& process, const std::vector<libmem::Module>& modules, int selected_module);

// Module dumping
void dump_module(const libmem::Process& process, const libmem::Module& module); 