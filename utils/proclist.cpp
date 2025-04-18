#include "utils.h"
#include "disasm.h"
#include "watcher.h"



/**
 * Displays a menu of actions that can be performed on a process/module
 * 
 * @param process The process to perform actions on
 * @param module Optional module if a specific module was selected
 * @return The selected action
 */
ProcessAction show_process_actions(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt) {
    // Module information text
    std::string module_info = module.has_value() ? 
        module->name + " (Base: 0x" + std::to_string(module->base) + ")" : 
        "All Modules";
    
    while (true) {
        // Clear the screen
        #ifdef _WIN32
        system("cls");
        #else
        system("clear");
        #endif
        
        std::cout << "===== PROCESS ACTIONS =====" << std::endl;
        std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
        std::cout << "Module: " << module_info << std::endl;
        std::cout << "===========================" << std::endl;
        std::cout << "1. Scan for array of bytes" << std::endl;
        std::cout << "2. Enter memory address" << std::endl;
        std::cout << "3. Back to module selection" << std::endl;
        std::cout << "q. Quit" << std::endl;
        std::cout << "===========================" << std::endl;
        std::cout << "Enter your choice: ";
        
        std::string input;
        std::getline(std::cin, input);
        
        if (input == "1") {
            return ProcessAction::SCAN_BYTES;
        } else if (input == "2") {
            return ProcessAction::ENTER_ADDRESS;
        } else if (input == "3") {
            return ProcessAction::BACK_TO_MODULES;
        } else if (input == "q" || input == "Q") {
            return ProcessAction::CANCEL;
        } else {
            std::cout << "Invalid input. Press Enter to continue...";
            std::cin.ignore();
        }
    }
}

/**
 * Enter a specific memory address to examine
 * 
 * @param process The process to examine
 * @param module Optional module context
 */
void enter_memory_address(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt) {
    // Module information text
    std::string module_info = module.has_value() ? 
        module->name + " (Base: 0x" + std::to_string(module->base) + ")" : 
        "All Modules";
    
    // Clear the screen
    #ifdef _WIN32
    system("cls");
    #else
    system("clear");
    #endif
    
    std::cout << "===== ENTER MEMORY ADDRESS =====" << std::endl;
    std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
    std::cout << "Module: " << module_info << std::endl;
    std::cout << "================================" << std::endl;
    std::cout << "Enter memory address (e.g., 0x7FF45CB00000), or 'q' to cancel:" << std::endl;
    std::cout << "> ";
    
    std::string address_input;
    std::getline(std::cin, address_input);
    
    if (address_input == "q" || address_input == "Q") {
        return;
    }
    
    // Parse the address
    libmem::Address parsed_address = 0;
    bool valid_address = false;
    
    try {
        // Try to parse the address - support both decimal and hex
        if (address_input.substr(0, 2) == "0x") {
            parsed_address = std::stoull(address_input.substr(2), nullptr, 16);
        } else {
            parsed_address = std::stoull(address_input, nullptr, 0);
        }
        
        // Validate the address (basic check)
        if (parsed_address == 0) {
            std::cout << "Invalid address: cannot be zero" << std::endl;
            std::cout << "Press Enter to return...";
            std::cin.ignore();
            return;
        }
        
        valid_address = true;
    } catch (const std::exception& e) {
        std::cout << "Invalid address format: " << e.what() << std::endl;
        std::cout << "Press Enter to return...";
        std::cin.ignore();
        return;
    }
    
    if (valid_address) {
        std::cout << "Address parsed: 0x" << std::hex << parsed_address << std::dec << std::endl;
        
        // Ask user what to do with the address
        std::cout << "================================" << std::endl;
        std::cout << "1. Disassemble memory at address" << std::endl;
        std::cout << "2. Watch memory at address" << std::endl;
        std::cout << "3. Return to previous menu" << std::endl;
        std::cout << "Enter your choice: ";
        
        std::string choice;
        std::getline(std::cin, choice);
        
        if (choice == "1") {
            // Disassemble memory
            disassemble_memory_region(process, parsed_address);
        } else if (choice == "2") {
            // Watch memory
            watch_memory_region(process, parsed_address, 16);  // Default to 16 bytes
        }
    }
}

/**
 * Displays a list of processes using libmem, allowing the user to select one.
 * 
 * @return The PID of the selected process, or 0 if failed/canceled
 */
libmem::Pid process_select() {
    std::cout << "Loading processes..." << std::endl;
    
    // Get processes using libmem
    std::vector<libmem::Process> processes;
    auto processes_opt = libmem::EnumProcesses();
    
    if (!processes_opt.has_value()) {
        std::cout << "Failed to enumerate processes." << std::endl;
        return 0;
    }
    
    processes = processes_opt.value();
    std::cout << "Found " << processes.size() << " processes" << std::endl;
    
    // Filter variable
    std::string filter;
    std::vector<libmem::Process> filtered_processes;
    bool quit = false;
    
    while (!quit) {
        // Clear the screen
        #ifdef _WIN32
        system("cls");
        #else
        system("clear");
        #endif
        
        std::cout << "===== PROCESS SELECTION =====" << std::endl;
        if (!filter.empty()) {
            std::cout << "Filter: " << filter << std::endl;
        }
        std::cout << "===========================" << std::endl;
        
        // Apply filter
        filtered_processes.clear();
        if (filter.empty()) {
            filtered_processes = processes;
        } else {
            for (const auto& process : processes) {
                std::string name_lower = process.name;
                std::string pid_str = std::to_string(process.pid);
                
                std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                
                std::string filter_lower = filter;
                std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                
                if (name_lower.find(filter_lower) != std::string::npos || 
                    pid_str.find(filter) != std::string::npos) {
                    filtered_processes.push_back(process);
                }
            }
        }
        
        // Display processes (paginated if more than 20)
        const int page_size = 20;
        int page = 0;
        int max_page = (filtered_processes.size() - 1) / page_size;
        
        while (true) {
            #ifdef _WIN32
            system("cls");
            #else
            system("clear");
            #endif
            
            std::cout << "===== PROCESS SELECTION =====" << std::endl;
            if (!filter.empty()) {
                std::cout << "Filter: " << filter << std::endl;
            }
            std::cout << "Page " << (page + 1) << " of " << (max_page + 1) << std::endl;
            std::cout << "===========================" << std::endl;
            
            int start_idx = page * page_size;
            int end_idx = std::min((page + 1) * page_size, (int)filtered_processes.size());
            
            for (int i = start_idx; i < end_idx; i++) {
                const auto& process = filtered_processes[i];
                std::cout << (i - start_idx + 1) << ". PID: " << process.pid 
                          << " | " << process.name << std::endl;
            }
            
            std::cout << "===========================" << std::endl;
            std::cout << "Enter process number to select, or:" << std::endl;
            std::cout << "f - Filter processes" << std::endl;
            if (page < max_page) std::cout << "n - Next page" << std::endl;
            if (page > 0) std::cout << "p - Previous page" << std::endl;
            std::cout << "q - Quit" << std::endl;
            std::cout << "Choice: ";
            
            std::string input;
            std::getline(std::cin, input);
            
            // Check for commands
            if (input == "q" || input == "Q") {
                return 0;
            } else if ((input == "n" || input == "N") && page < max_page) {
                page++;
                continue;
            } else if ((input == "p" || input == "P") && page > 0) {
                page--;
                continue;
            } else if (input == "f" || input == "F") {
                std::cout << "Enter filter (process name or PID): ";
                std::getline(std::cin, filter);
                break; // Break the inner loop to reapply filter
            } else {
                // Try to parse as a number
                try {
                    int idx = std::stoi(input) - 1 + start_idx;
                    if (idx >= 0 && idx < (int)filtered_processes.size()) {
                        return filtered_processes[idx].pid;
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
    
    return 0;
}