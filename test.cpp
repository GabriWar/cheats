#include "utils/utils.h"
#include "utils/proclist.h"
#include "utils/modulelist.h"
#include "utils/sigscan.h"
#include "utils/disasm.h"
#include "utils/watcher.h"

// Simple console menu system
void clearScreen() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

void printHeader(const std::string& title) {
    clearScreen();
    std::cout << "====================================" << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << "====================================" << std::endl;
}

int main() {
    bool quit = false;
    
    while (!quit) {
        printHeader("MEMORY CHEAT TOOL");
        std::cout << "Selecting a process..." << std::endl;
        
        // Process selection
        libmem::Pid selected_pid = process_select();
        
        if (selected_pid == 0) {
            std::cout << "No process selected or operation canceled." << std::endl;
            std::cout << "Press Enter to exit...";
            std::cin.ignore();
            quit = true;
            continue;
        }
        
        std::cout << "Process selected with PID: " << selected_pid << std::endl;
        
        // Loop for module selection - allows going back to process selection
        bool back_to_process_list = false;
        while (!back_to_process_list && !quit) {
            // Show modules for the selected process
            ModuleSelectionResult module_result = show_process_modules(selected_pid);
            
            if (module_result.back_to_process_list) {
                back_to_process_list = true;
                std::cout << "Going back to process list..." << std::endl;
            } else if (module_result.success) {
                if (module_result.select_all_modules) {
                    std::cout << "All modules selected. Total modules: " << 
                              module_result.all_modules.size() << std::endl;
                    
                    // Show actions menu for all modules
                    ProcessAction action = show_process_actions(libmem::GetProcess(selected_pid).value(), std::nullopt);
                    
                    switch (action) {
                        case ProcessAction::SCAN_BYTES:
                            scan_for_bytes(libmem::GetProcess(selected_pid).value(), std::nullopt);
                            break;
                        case ProcessAction::ENTER_ADDRESS:
                            enter_memory_address(libmem::GetProcess(selected_pid).value(), std::nullopt);
                            break;
                        case ProcessAction::BACK_TO_MODULES:
                            break;
                        case ProcessAction::CANCEL:
                            quit = true;
                            break;
                    }
                } else {
                    std::cout << "Working with module: " << module_result.selected_module->name << std::endl;
                    
                    // Show actions for the selected module
                    ProcessAction action = show_process_actions(libmem::GetProcess(selected_pid).value(), module_result.selected_module);
                    
                    switch (action) {
                        case ProcessAction::SCAN_BYTES:
                            scan_for_bytes(libmem::GetProcess(selected_pid).value(), module_result.selected_module);
                            break;
                        case ProcessAction::ENTER_ADDRESS:
                            enter_memory_address(libmem::GetProcess(selected_pid).value(), module_result.selected_module);
                            break;
                        case ProcessAction::BACK_TO_MODULES:
                            break;
                        case ProcessAction::CANCEL:
                            quit = true;
                            break;
                    }
                }
            } else {
                // Selection was canceled or failed
                quit = true;
                break;
            }
        }
    }
    
    return 0;
}