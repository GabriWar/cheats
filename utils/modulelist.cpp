#include "utils.h"
#include "disasm.h"
#include "sigscan.h"
#include "watcher.h"
#include "proclist.h"
#include "moduledump.h"

/**
 * Displays a list of modules in a process using console interface.
 * 
 * @param process The process to show modules for
 * @return ModuleSelectionResult containing selected module information
 */
ModuleSelectionResult module_select(const libmem::Process& process) {
    ModuleSelectionResult result;
    
    std::cout << "Getting modules for process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
    
    // Get modules using libmem
    std::vector<libmem::Module> modules;
    auto modules_opt = libmem::EnumModules(&process);
    
    if (!modules_opt.has_value()) {
        std::cout << "Failed to enumerate modules." << std::endl;
        return result;
    }
    
    modules = modules_opt.value();
    result.all_modules = modules; // Store all modules in the result
    std::cout << "Found " << modules.size() << " modules" << std::endl;
    
    std::string filter_value;
    std::vector<libmem::Module> filtered_modules = modules;
    
    while (true) {
        // Clear the screen
        #ifdef _WIN32
        system("cls");
        #else
        system("clear");
        #endif
        
        std::cout << "===== MODULE LIST =====" << std::endl;
        std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
        std::cout << "======================" << std::endl;
        
        if (!filter_value.empty()) {
            std::cout << "Filter: " << filter_value << std::endl;
            std::cout << "======================" << std::endl;
        }
        
        // Display "Select All Modules" option first
        std::cout << "0. [Select All Modules]" << std::endl;
        
        // Display modules with index numbers
        int idx = 1;
        for (const auto& module : filtered_modules) {
            std::cout << idx << ". " << module.name << " (Base: 0x" 
                     << std::hex << module.base << std::dec 
                     << ", Size: " << module.size << " bytes)" << std::endl;
            idx++;
        }
        
        std::cout << "======================" << std::endl;
        std::cout << "f: Filter modules" << std::endl;
        std::cout << "b: Back to process list" << std::endl;
        std::cout << "q: Quit" << std::endl;
        std::cout << "======================" << std::endl;
        std::cout << "Enter your choice: ";
        
        std::string input;
        std::getline(std::cin, input);
        
        // Filter modules
        if (input == "f" || input == "F") {
            std::cout << "Enter filter (module name or address): ";
            std::getline(std::cin, filter_value);
            
            // Apply filtering
            filtered_modules.clear();
            
            if (filter_value.empty()) {
                filtered_modules = modules;
            } else {
                // Convert filter to lowercase for case-insensitive comparison
                std::string filter_lower = filter_value;
                std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                
                // Filter modules by name or address
                for (const auto& module : modules) {
                    std::string name_lower = module.name;
                    std::string path_lower = module.path;
                    std::stringstream addr_stream;
                    addr_stream << std::hex << module.base;
                    std::string addr_str = "0x" + addr_stream.str();
                    
                    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                                  [](unsigned char c){ return std::tolower(c); });
                    std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(),
                                  [](unsigned char c){ return std::tolower(c); });
                    
                    if (name_lower.find(filter_lower) != std::string::npos || 
                        path_lower.find(filter_lower) != std::string::npos ||
                        addr_str.find(filter_value) != std::string::npos) {
                        filtered_modules.push_back(module);
                    }
                }
            }
            continue;
        }
        
        // Back to process list
        if (input == "b" || input == "B") {
            result.back_to_process_list = true;
            return result;
        }
        
        // Quit
        if (input == "q" || input == "Q") {
            return result;
        }
        
        // Try to parse as a number
        try {
            int selection = std::stoi(input);
            
            // Select All Modules
            if (selection == 0) {
                result.success = true;
                result.select_all_modules = true;
                return result;
            }
            // Individual module selection
            else if (selection > 0 && selection <= static_cast<int>(filtered_modules.size())) {
                result.success = true;
                result.selected_module = filtered_modules[selection - 1];
                return result;
            } else {
                std::cout << "Invalid selection. Press Enter to continue...";
                std::cin.get();
            }
        } catch (const std::exception&) {
            std::cout << "Invalid input. Press Enter to continue...";
            std::cin.get();
        }
    }
    
    return result;
}

/**
 * Displays a list of modules in a process.
 * 
 * @param process_pid The PID of the process to show modules for
 * @return ModuleSelectionResult containing selected module information
 */
ModuleSelectionResult show_process_modules(libmem::Pid process_pid) {
    ModuleSelectionResult result;
    
    // Get the process
    auto process_opt = libmem::GetProcess(process_pid);
    if (!process_opt.has_value()) {
        std::cout << "Failed to get process with PID: " << process_pid << std::endl;
        return result;
    }
    
    auto process = process_opt.value();
    std::cout << "Getting modules for process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
    
    // Get modules using libmem
    std::vector<libmem::Module> modules;
    auto modules_opt = libmem::EnumModules(&process);
    
    if (!modules_opt.has_value()) {
        std::cout << "Failed to enumerate modules." << std::endl;
        return result;
    }
    
    modules = modules_opt.value();
    result.all_modules = modules; // Store all modules in the result
    std::cout << "Found " << modules.size() << " modules" << std::endl;
    
    // Filter variable
    std::string filter;
    std::vector<libmem::Module> filtered_modules;
    bool quit = false;
    
    while (!quit) {
        // Clear the screen
        #ifdef _WIN32
        system("cls");
        #else
        system("clear");
        #endif
        
        std::cout << "===== MODULE SELECTION =====" << std::endl;
        std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
        if (!filter.empty()) {
            std::cout << "Filter: " << filter << std::endl;
        }
        std::cout << "===========================" << std::endl;
        
        // Special option for "All Modules"
        std::cout << "0. [Select All Modules]" << std::endl;
        
        // Apply filter
        filtered_modules.clear();
        if (filter.empty()) {
            filtered_modules = modules;
        } else {
            for (const auto& module : modules) {
                std::string name_lower = module.name;
                std::string path_lower = module.path;
                std::string addr_str = "0x" + std::to_string(module.base);
                
                std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                
                std::string filter_lower = filter;
                std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                
                if (name_lower.find(filter_lower) != std::string::npos || 
                    path_lower.find(filter_lower) != std::string::npos ||
                    addr_str.find(filter) != std::string::npos) {
                    filtered_modules.push_back(module);
                }
            }
        }
        
        // Display modules (paginated if more than 20)
        const int page_size = 20;
        int page = 0;
        int max_page = (filtered_modules.size() - 1) / page_size;
        
        while (true) {
            #ifdef _WIN32
            system("cls");
            #else
            system("clear");
            #endif
            
            std::cout << "===== MODULE SELECTION =====" << std::endl;
            std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
            if (!filter.empty()) {
                std::cout << "Filter: " << filter << std::endl;
            }
            std::cout << "Page " << (page + 1) << " of " << (max_page + 1) << std::endl;
            std::cout << "===========================" << std::endl;
            
            // Always show "All Modules" option
            std::cout << "0. [Select All Modules]" << std::endl;
            
            int start_idx = page * page_size;
            int end_idx = std::min((page + 1) * page_size, (int)filtered_modules.size());
            
            for (int i = start_idx; i < end_idx; i++) {
                const auto& module = filtered_modules[i];
                std::cout << (i - start_idx + 1) << ". " << module.name 
                          << " (Base: 0x" << std::hex << module.base << std::dec
                          << ", Size: " << module.size << " bytes)" << std::endl;
            }
            
            std::cout << "===========================" << std::endl;
            std::cout << "Enter module number to select, or:" << std::endl;
            std::cout << "f - Filter modules" << std::endl;
            if (page < max_page) std::cout << "n - Next page" << std::endl;
            if (page > 0) std::cout << "p - Previous page" << std::endl;
            std::cout << "b - Back to process selection" << std::endl;
            std::cout << "q - Quit" << std::endl;
            std::cout << "Choice: ";
            
            std::string input;
            std::getline(std::cin, input);
            
            // Check for commands
            if (input == "q" || input == "Q") {
                result.success = false;
                return result;
            } else if (input == "b" || input == "B") {
                result.back_to_process_list = true;
                return result;
            } else if ((input == "n" || input == "N") && page < max_page) {
                page++;
                continue;
            } else if ((input == "p" || input == "P") && page > 0) {
                page--;
                continue;
            } else if (input == "f" || input == "F") {
                std::cout << "Enter filter (module name or address): ";
                std::getline(std::cin, filter);
                break; // Break the inner loop to reapply filter
            } else if (input == "0") {
                // Select all modules
                result.success = true;
                result.select_all_modules = true;
                return result;
            } else {
                // Try to parse as a number
                try {
                    int idx = std::stoi(input) - 1 + start_idx;
                    if (idx >= 0 && idx < (int)filtered_modules.size()) {
                        result.success = true;
                        result.selected_module = filtered_modules[idx];
                        return result;
                    } else {
                        std::cout << "Invalid selection. Press Enter to continue...";
                        std::cin.ignore();
                    }
                } catch (const std::exception& e) {
                    std::cout << "Invalid input. Press Enter to continue...";
                    std::cin.ignore();
                }
            }
        }
    }
    
    return result;
}

/**
 * Console-based module action menu
 * 
 * @param process The process to perform actions on
 * @param modules List of all modules in the process
 * @param selected_module Index of the selected module (-1 for all modules)
 */
void handle_module_menu(const libmem::Process& process, const std::vector<libmem::Module>& modules, int selected_module) {
    std::string module_name;
    if (selected_module == -1) {
        module_name = "All Modules";
    } else {
        module_name = modules[selected_module].name;
    }
    
    bool back_to_module_list = false;
    
    while (!back_to_module_list) {
        // Clear the screen
        #ifdef _WIN32
        system("cls");
        #else
        system("clear");
        #endif
        
        std::cout << "===== MODULE ACTIONS =====" << std::endl;
        std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
        std::cout << "Module: " << module_name << std::endl;
        std::cout << "=========================" << std::endl;
        std::cout << "1. Dump module" << std::endl;
        std::cout << "2. Find bytes in memory" << std::endl;
        std::cout << "3. Disassemble memory region" << std::endl;
        std::cout << "4. Watch memory region" << std::endl;
        std::cout << "5. Enter memory address" << std::endl;
        std::cout << "6. Back to module list" << std::endl;
        std::cout << "q. Quit" << std::endl;
        std::cout << "=========================" << std::endl;
        std::cout << "Enter your choice: ";
        
        std::string input;
        std::getline(std::cin, input);
        
        if (input == "1") {
            // Dump module
            if (selected_module != -1) {
                dump_module(process, modules[selected_module]);
            }
        } else if (input == "2") {
            // Find bytes
            if (selected_module != -1) {
                find_bytes(process, modules[selected_module]);
            } else {
                find_bytes(process, std::nullopt);
            }
        } else if (input == "3") {
            // Disassemble memory region
            if (selected_module != -1) {
                disassemble_memory_region(process, modules[selected_module].base);
            }
        } else if (input == "4") {
            // Watch memory region
            if (selected_module != -1) {
                watch_memory_region(process, modules[selected_module].base);
            }
        } else if (input == "5") {
            // Enter memory address
            if (selected_module != -1) {
                enter_memory_address(process, modules[selected_module]);
            } else {
                enter_memory_address(process);
            }
        } else if (input == "6" || input == "b" || input == "B") {
            // Back to module list
            back_to_module_list = true;
        } else if (input == "q" || input == "Q") {
            exit(0);
        } else {
            std::cout << "Invalid input. Press Enter to continue...";
            std::cin.ignore();
        }
    }
}

/**
 * Dump a module's information and memory to console
 * 
 * @param process The process containing the module
 * @param module The module to dump
 */
void dump_module(const libmem::Process& process, const libmem::Module& module) {
    // Clear the screen
    #ifdef _WIN32
    system("cls");
    #else
    system("clear");
    #endif
    
    std::cout << "===== MODULE DUMP =====" << std::endl;
    std::cout << "Dumping module: " << module.name << std::endl;
    std::cout << "======================" << std::endl;
    
    // Add module information
    std::cout << "Module: " << module.name << std::endl;
    std::cout << "Path: " << module.path << std::endl;
    std::cout << "Base address: 0x" << std::hex << module.base << std::dec << std::endl;
    std::cout << "End address: 0x" << std::hex << module.end << std::dec << std::endl;
    std::cout << "Size: " << module.size << " bytes" << std::endl;
    std::cout << std::endl;
    
    // Add memory preview of the first 1024 bytes or less
    const size_t preview_size = std::min<size_t>(1024, module.size);
    std::vector<uint8_t> memory_buffer(preview_size, 0);
    size_t bytes_read = libmem::ReadMemory(&process, module.base, memory_buffer.data(), preview_size);
    
    if (bytes_read > 0) {
        std::cout << "Memory preview (first " << bytes_read << " bytes):" << std::endl;
        
        // Format the memory in rows of 16 bytes
        for (size_t offset = 0; offset < bytes_read; offset += 16) {
            std::stringstream line;
            line << "0x" << std::hex << (module.base + offset) << ": ";
            
            // Hex representation
            for (size_t i = 0; i < 16 && (offset + i) < bytes_read; i++) {
                char hex_buff[4];
                snprintf(hex_buff, sizeof(hex_buff), "%02X ", memory_buffer[offset + i]);
                line << hex_buff;
            }
            
            // Pad if less than 16 bytes
            const size_t remaining = bytes_read - offset;
            if (remaining < 16) {
                for (size_t i = 0; i < (16 - remaining); i++) {
                    line << "   ";
                }
                if (remaining <= 8) line << " "; // Extra space if we didn't print the second half
            }
            
            // ASCII representation
            line << " | ";
            for (size_t i = 0; i < 16 && (offset + i) < bytes_read; i++) {
                char c = memory_buffer[offset + i];
                line << (c >= 32 && c <= 126 ? c : '.');
            }
            
            std::cout << line.str() << std::endl;
            
            // Limit the number of lines to display
            if (offset >= 480) {  // Show about 30 lines (480/16)
                std::cout << "... (output truncated, module too large to display completely)" << std::endl;
                break;
            }
        }
    } else {
        std::cout << "Failed to read module memory." << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "Press Enter to return..." << std::endl;
    std::cin.ignore();
}