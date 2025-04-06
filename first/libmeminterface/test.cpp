///////////////////////////////////////////////////////////////////////////////
/////////////////////  PLATFORM-SPECIFIC CODE - START  /////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
    // Windows-specific includes
    #include <windows.h>
#else
    // Linux-specific includes
    #include <unistd.h>
#endif
#include "LIBMEMLIN/includeLIN/libmem/libmem.h"

///////////////////////////////////////////////////////////////////////////////
/////////////////////  PLATFORM-SPECIFIC CODE - END  ///////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Common includes for all platforms
#include <iostream>
#include <string>
#include <map>
#include <iomanip>
#include <ctime>

// Define a single global signature variable
const std::string GLOBAL_SIGNATURE = "48 8D 64 24 ? C6 05 ? ? ? ? ? 4C 8D 05";
const int DISASM_INSTRUCTIONS_COUNT = 10; // Number of instructions to disassemble before and after match

// Forward declarations
void ScanModulesWithSignature(lm_process_t& process, const std::map<std::string, lm_module_t>& module_map, 
                              const std::map<int, lm_module_t>* numbered_module_map, const std::string& signature);
bool WriteMemoryValue(lm_process_t* process, lm_address_t address, uint32_t* value_ptr);

inline bool ReadMemory(lm_process_t* process, lm_address_t address, void* buffer, size_t size) {
    return LM_ReadMemoryEx(process, address, (lm_byte_t*)buffer, size) != 0;
}

inline lm_size_t Disassemble(lm_address_t address, int instruction_count, lm_inst_t** instructions_out) {
    return LM_DisassembleEx(address, LM_GetArchitecture(), 0, instruction_count, address, instructions_out);
}




// Callback function to list processes and store them in a map
lm_bool_t ListProcessesCallback(lm_process_t* process, lm_void_t* arg) {
    auto* process_map = static_cast<std::map<lm_pid_t, std::string>*>(arg);
    (*process_map)[process->pid] = process->name;
    std::cout << "[" << process->pid << "] " << process->name << "\n";
    return LM_TRUE; // Continue enumeration
}

// Function to print memory value in various formats
void PrintMemoryValue(lm_address_t address, uint32_t value, uint32_t prev_value = 0, bool show_diff = false) {
    std::cout << "Memory at address 0x" << std::hex << address << ":\n";
    std::cout << "  As hex:      0x" << std::hex << std::setw(8) << std::setfill('0') << value << std::dec << "\n";
    std::cout << "  As int:      " << static_cast<int32_t>(value) << "\n";
    std::cout << "  As uint:     " << value << "\n";
    std::cout << "  As float:    " << *reinterpret_cast<float*>(&value) << "\n";
    
    // Show as pointer/address
    std::cout << "  As address:  0x" << std::hex << value << std::dec << "\n";
    
    // Show as bytes
    std::cout << "  As bytes:    ";
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&value);
    for (int i = 0; i < 4; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(bytes[i]) << " ";
    }
    std::cout << std::dec << "\n";
    
    // Show change if requested
    if (show_diff) {
        int32_t diff = static_cast<int32_t>(value) - static_cast<int32_t>(prev_value);
        std::cout << "  Change:      " << std::showpos << diff << std::noshowpos << "\n";
    }
}

// Function to read 4 bytes from memory - works on both Windows and Linux
void ReadMemoryDword(lm_process_t* process, lm_address_t address) {
    uint32_t value = 0;
    bool success = ReadMemory(process, address, &value, sizeof(value));

    if (success) {
        PrintMemoryValue(address, value);
    } else {
        std::cout << "Failed to read memory at address 0x" << std::hex << address << std::dec << "\n";
    }
}

// Function to disassemble memory around a specific address
void DisassembleMemoryRegion(lm_process_t* process, lm_address_t address, int instruction_count) {
    std::cout << "\nDisassembling memory around address: 0x" << std::hex << address << std::dec << "\n";
    std::cout << "----------------------------------------\n";
    
    lm_inst_t* instructions = nullptr;
    lm_size_t count = Disassemble(address, instruction_count, &instructions);
    
    if (count == 0 || !instructions) {
        std::cout << "Failed to disassemble memory region.\n";
        return;
    }
    
    for (lm_size_t i = 0; i < count; i++) {
        std::cout << std::hex << "0x" << instructions[i].address << std::dec << ":\t";
        std::cout << instructions[i].mnemonic << " " << instructions[i].op_str << "\n";
    }
    
    LM_FreeInstructions(instructions);
    std::cout << "----------------------------------------\n";
}

// Function to perform a signature scan in a module
void PerformSignatureScan(lm_process_t* process, lm_module_t* module, const std::string& signature) {
    std::cout << "Scanning module: " << module->name << "\n";
    std::cout << "Signature: " << signature << "\n";

    lm_address_t address = module->base;
    lm_size_t size = module->size;
    
    // Perform the signature scan
    lm_address_t result = LM_SigScanEx(process, signature.c_str(), address, size);
    
    if (result != LM_ADDRESS_BAD) {
        // First show the match information clearly
        std::cout << "\nSignature found in module " << module->name << " at address: 0x" 
                  << std::hex << result << std::dec << "\n";
        
        // Then display the menu
        std::cout << "Choose an action:\n";
        std::cout << "1. Disassemble memory region\n";
        std::cout << "2. Read 4-byte value at address\n";
        std::cout << "3. Both disassemble and read value\n";
        std::cout << "4. Skip\n";
        std::cout << "Enter your choice (1-4): ";
        
        char action_choice;
        std::cin >> action_choice;
        
        switch (action_choice) {
            case '1':
                DisassembleMemoryRegion(process, result, DISASM_INSTRUCTIONS_COUNT);
                break;
            case '2':
                ReadMemoryDword(process, result);
                break;
            case '3':
                DisassembleMemoryRegion(process, result, DISASM_INSTRUCTIONS_COUNT);
                ReadMemoryDword(process, result);
                break;
            case '4':
            default:
                std::cout << "Skipping this match.\n";
                break;
        }
    } else {
        std::cout << "Signature not found in module " << module->name << "\n";
    }
}

struct ModuleContext {
    int index;
    std::map<std::string, lm_module_t>* module_map;
    std::map<int, lm_module_t>* numbered_module_map;
};

// Define ModuleEnumerationContext to fix the undefined identifier error
struct ModuleEnumerationContext {
    int index;
    std::map<int, lm_module_t>* numbered_module_map;
};

lm_bool_t ListModulesCallback(lm_module_t* module, lm_void_t* arg) {
    auto* context = static_cast<ModuleContext*>(arg);
    context->module_map->emplace(module->name, *module);

    if (context->numbered_module_map) {
        context->numbered_module_map->emplace(context->index, *module);
        std::cout << "[" << context->index << "] " << module->name << "\n";
        context->index++;
    }

    return LM_TRUE; // Continue enumeration
}

void ListModules(lm_process_t& process, std::map<std::string, lm_module_t>& module_map, std::map<int, lm_module_t>* numbered_module_map = nullptr) {
    std::cout << "Listing all modules in process: " << process.name << "\n";
    ModuleContext context = {1, &module_map, numbered_module_map};
    LM_EnumModulesEx(&process, ListModulesCallback, &context);
}

void ListModulesWithNumbers(lm_process_t& process, std::map<int, lm_module_t>& numbered_module_map) {
    std::cout << "Listing all modules in process: " << process.name << "\n";
    ModuleEnumerationContext context = {1, &numbered_module_map};
    LM_EnumModulesEx(&process, ListModulesCallback, &context);
}

void ScanModules(lm_process_t& process, const std::map<std::string, lm_module_t>& module_map, const std::map<int, lm_module_t>* numbered_module_map = nullptr) {
    if (numbered_module_map) {
        int module_index;
        std::cout << "Enter the number of the module to scan (or type '0' to scan all modules): ";
        std::cin >> module_index;

        if (module_index == 0) {
            for (const auto& pair : *numbered_module_map) {
                const lm_module_t& module = pair.second;
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&module), GLOBAL_SIGNATURE);
            }
        } else {
            if (numbered_module_map->find(module_index) != numbered_module_map->end()) {
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&numbered_module_map->at(module_index)), GLOBAL_SIGNATURE);
            } else {
                std::cerr << "Invalid module number: " << module_index << "\n";
            }
        }
    } else {
        std::string module_name;
        std::cout << "Enter the module name to scan (or type 'all' to scan all modules): ";
        std::cin.ignore(); // Clear the input buffer
        std::getline(std::cin, module_name);

        if (module_name == "all") {
            for (const auto& pair : module_map) {
                const std::string& name = pair.first;
                const lm_module_t& module = pair.second;
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&module), GLOBAL_SIGNATURE);
            }
        } else {
            if (module_map.find(module_name) != module_map.end()) {
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&module_map.at(module_name)), GLOBAL_SIGNATURE);
            } else {
                std::cerr << "Invalid module name: " << module_name << "\n";
            }
        }
    }
}

// Allow user to read a 4-byte value at a custom address
void ReadCustomAddress(lm_process_t* process) {
    lm_address_t address;
    std::cout << "Enter memory address to read (in hex format, e.g., 0x12345678): ";
    std::cin >> std::hex >> address >> std::dec;
    
    ReadMemoryDword(process, address);
}

// Allow user to read a 4-byte value at a custom address in a loop
void ReadCustomAddressLoop(lm_process_t* process) {
    lm_address_t address;
    std::cout << "Enter memory address to monitor (in hex format, e.g., 0x12345678): ";
    std::cin >> std::hex >> address >> std::dec;
    
    std::cout << "Monitoring address 0x" << std::hex << address << std::dec << " (Press Ctrl+C to stop)...\n";
    std::cout << "Commands while monitoring:\n";
    std::cout << "  Type 'f' to freeze/unfreeze the value\n";
    std::cout << "  Type 'c' to change the value\n";
    std::cout << "  Press Enter to continue monitoring\n";
    std::cout << "----------------------------------------\n";
    
    uint32_t prev_value = 0;
    uint32_t frozen_value = 0;
    bool first_read = true;
    bool is_frozen = false;
    unsigned long long loop_count = 0;
    char input_command;
    
    while (true) {
        uint32_t value = 0;
        bool success = ReadMemory(process, address, &value, sizeof(value));

        if (success) {
            // If frozen, write the frozen value back to memory
            if (is_frozen) {
                // Write frozen value back to memory
                LM_WriteMemoryEx(process, address, reinterpret_cast<lm_byte_t*>(&frozen_value), sizeof(frozen_value));
                
                // Display status every 1000 loops to avoid spamming the console
                if (loop_count % 1000 == 0) {
                    std::cout << "Time: " << std::time(nullptr) << " | ";
                    std::cout << "FROZEN | Value: 0x" << std::hex << std::setw(8) << std::setfill('0') 
                              << frozen_value << std::dec << "\n";
                }
                value = frozen_value;
            }
            else {
                // Only print if the value changed or it's the first read (when not frozen)
                if (first_read || value != prev_value) {
                    std::cout << "Time: " << std::time(nullptr) << " | ";
                    std::cout << "Loop count: " << loop_count << " | ";
                    
                    // Use the common print function
                    PrintMemoryValue(address, value, prev_value, !first_read);
                    
                    prev_value = value;
                    first_read = false;
                }
            }
        } else {
            std::cout << "Failed to read memory at address 0x" << std::hex << address << std::dec << "\n";
            break;
        }
        
        // Check for user commands without blocking (non-blocking input)
        if (std::cin.rdbuf()->in_avail() > 0) {
            std::cin >> input_command;
            
            // Process command
            if (input_command == 'f' || input_command == 'F') {
                if (!is_frozen) {
                    // Freeze the current value
                    is_frozen = true;
                    frozen_value = value;
                    std::cout << "Value FROZEN at 0x" << std::hex << std::setw(8) << std::setfill('0') 
                              << frozen_value << std::dec << "\n";
                } else {
                    // Unfreeze
                    is_frozen = false;
                    std::cout << "Value UNFROZEN\n";
                }
            } else if (input_command == 'c' || input_command == 'C') {
                // Allow changing the value
                uint32_t current_value = is_frozen ? frozen_value : value;
                
                // Show current value first
                std::cout << "\nCurrent value:\n";
                PrintMemoryValue(address, current_value);
                
                // Change the value
                if (WriteMemoryValue(process, address, &current_value)) {
                    if (is_frozen) {
                        // Update frozen value if we're in frozen mode
                        frozen_value = current_value;
                        std::cout << "Frozen value updated to 0x" << std::hex << std::setw(8) 
                                  << std::setfill('0') << frozen_value << std::dec << "\n";
                    }
                }
            }
            
            // Clear any remaining input
            std::cin.clear();
            std::cin.ignore(10000, '\n');
        }
        
        // Increment loop counter for monitoring purposes
        loop_count++;
    }
}

// Fix type mismatch in HandleModuleListingAndScanning
void HandleModuleListingAndScanning(lm_process_t& process) {
    char list_modules_choice;
    std::cout << "Do you want to list all modules inside the process? (y/n): ";
    std::cin >> list_modules_choice;

    if (list_modules_choice == 'y' || list_modules_choice == 'Y') {
        std::map<std::string, lm_module_t> module_map;
        std::map<int, lm_module_t> numbered_module_map;
        ListModules(process, module_map, &numbered_module_map);

        ScanModules(process, module_map, &numbered_module_map); // Pass both maps correctly
    } else {
        std::cout << "Skipping module listing.\n";
    }
}

// Function to write a value to memory in different formats
bool WriteMemoryValue(lm_process_t* process, lm_address_t address, uint32_t* value_ptr) {
    std::cout << "\nSelect value format to write:\n";
    std::cout << "1. Hexadecimal (e.g., 0xA1B2C3D4)\n";
    std::cout << "2. Integer (e.g., -123456)\n";
    std::cout << "3. Unsigned integer (e.g., 3000000000)\n";
    std::cout << "4. Float (e.g., 3.14159)\n";
    std::cout << "5. Four bytes (e.g., FF AA BB CC)\n";
    std::cout << "6. Cancel\n";
    std::cout << "Enter your choice (1-6): ";
    
    int choice;
    std::cin >> choice;
    
    uint32_t new_value = 0;
    bool valid_input = false;
    
    switch (choice) {
        case 1: { // Hex
            std::cout << "Enter new value in hex (e.g., AABBCCDD or 0xAABBCCDD): ";
            std::cin >> std::hex >> new_value >> std::dec;
            valid_input = true;
            break;
        }
        case 2: { // Integer
            int32_t int_val;
            std::cout << "Enter new value as integer: ";
            std::cin >> int_val;
            new_value = *reinterpret_cast<uint32_t*>(&int_val);
            valid_input = true;
            break;
        }
        case 3: { // Unsigned int
            std::cout << "Enter new value as unsigned integer: ";
            std::cin >> new_value;
            valid_input = true;
            break;
        }
        case 4: { // Float
            float float_val;
            std::cout << "Enter new value as float: ";
            std::cin >> float_val;
            new_value = *reinterpret_cast<uint32_t*>(&float_val);
            valid_input = true;
            break;
        }
        case 5: { // Four bytes
            uint8_t bytes[4] = {0};
            std::cout << "Enter 4 bytes separated by spaces (e.g., FF AA BB CC): ";
            for (int i = 0; i < 4; i++) {
                unsigned int byte;
                std::cin >> std::hex >> byte >> std::dec;
                bytes[i] = static_cast<uint8_t>(byte);
            }
            // Write bytes directly to memory
            if (LM_WriteMemoryEx(process, address, bytes, 4)) {
                // Read back the value to update in the caller
                if (ReadMemory(process, address, &new_value, sizeof(new_value))) {
                    *value_ptr = new_value;
                    std::cout << "Value successfully written to memory.\n";
                    return true;
                }
            }
            std::cout << "Failed to write value to memory!\n";
            return false;
        }
        case 6: // Cancel
        default:
            std::cout << "Operation cancelled.\n";
            return false;
    }
    
    if (valid_input) {
        // Write to memory
        if (LM_WriteMemoryEx(process, address, reinterpret_cast<lm_byte_t*>(&new_value), sizeof(new_value))) {
            std::cout << "Value successfully written to memory.\n";
            *value_ptr = new_value; // Update the value in the caller
            return true;
        } else {
            std::cout << "Failed to write value to memory!\n";
        }
    }
    
    return false;
}

// Main menu options
void ShowMainMenu(lm_process_t& process) {
    int choice = 0;
    std::string custom_signature;
    
    while (true) {
        std::cout << "\n===== MEMORY INTERFACE MAIN MENU =====\n";
        std::cout << "1. List modules in process\n";
        std::cout << "2. Enter signature manually\n";
        std::cout << "3. Scan modules with default signature\n";
        std::cout << "4. Read memory at address\n";
        std::cout << "5. Monitor memory at address\n";
        std::cout << "6. Exit\n";
        std::cout << "Enter your choice (1-6): ";
        std::cin >> choice;
        
        switch (choice) {
            case 1: {
                // List modules
                std::map<std::string, lm_module_t> module_map;
                std::map<int, lm_module_t> numbered_module_map;
                ListModules(process, module_map, &numbered_module_map);
                break;
            }
            case 2: {
                // Enter signature manually
                std::cin.ignore(); // Clear input buffer
                std::cout << "Enter signature (e.g., 48 8D 64 24 ? C6 05 ? ? ? ? ? 4C 8D 05): ";
                std::getline(std::cin, custom_signature);
                
                // List modules for scanning
                std::map<std::string, lm_module_t> module_map;
                std::map<int, lm_module_t> numbered_module_map;
                ListModules(process, module_map, &numbered_module_map);
                
                // Use the custom signature for scanning
                ScanModulesWithSignature(process, module_map, &numbered_module_map, custom_signature);
                break;
            }
            case 3: {
                // Scan modules with default signature
                std::map<std::string, lm_module_t> module_map;
                std::map<int, lm_module_t> numbered_module_map;
                ListModules(process, module_map, &numbered_module_map);
                ScanModules(process, module_map, &numbered_module_map);
                break;
            }
            case 4: {
                // Read memory at address
                ReadCustomAddress(&process);
                break;
            }
            case 5: {
                // Monitor memory at address
                ReadCustomAddressLoop(&process);
                break;
            }
            case 6:
                std::cout << "Exiting program...\n";
                return;
            default:
                std::cout << "Invalid choice, please try again.\n";
                break;
        }
    }
}

// Function to scan modules with a custom signature
void ScanModulesWithSignature(lm_process_t& process, const std::map<std::string, lm_module_t>& module_map, 
                              const std::map<int, lm_module_t>* numbered_module_map, const std::string& signature) {
    if (numbered_module_map) {
        int module_index;
        std::cout << "Enter the number of the module to scan (or type '0' to scan all modules): ";
        std::cin >> module_index;

        if (module_index == 0) {
            for (const auto& pair : *numbered_module_map) {
                const lm_module_t& module = pair.second;
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&module), signature);
            }
        } else {
            if (numbered_module_map->find(module_index) != numbered_module_map->end()) {
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&numbered_module_map->at(module_index)), signature);
            } else {
                std::cerr << "Invalid module number: " << module_index << "\n";
            }
        }
    } else {
        std::string module_name;
        std::cout << "Enter the module name to scan (or type 'all' to scan all modules): ";
        std::cin.ignore(); // Clear the input buffer
        std::getline(std::cin, module_name);

        if (module_name == "all") {
            for (const auto& pair : module_map) {
                const std::string& name = pair.first;
                const lm_module_t& module = pair.second;
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&module), signature);
            }
        } else {
            if (module_map.find(module_name) != module_map.end()) {
                PerformSignatureScan(&process, const_cast<lm_module_t*>(&module_map.at(module_name)), signature);
            } else {
                std::cerr << "Invalid module name: " << module_name << "\n";
            }
        }
    }
}

int main(int argc, char* argv[]) {
    lm_pid_t selected_pid = 0;

    // If no arguments are passed, list processes and prompt the user to select one by PID
    if (argc < 2) {
        std::cout << "No arguments passed. Listing all processes...\n";

        std::map<lm_pid_t, std::string> process_map;
        LM_EnumProcesses(ListProcessesCallback, &process_map);

        std::cout << "Enter the PID of the process: ";
        std::cin >> selected_pid;

        if (process_map.find(selected_pid) == process_map.end()) {
            std::cerr << "Invalid PID selected.\n";
            return 1;
        }
    } else {
        selected_pid = std::stoi(argv[1]);
    }

    lm_process_t process;

    // Find the process by PID
    if (!LM_GetProcessEx(selected_pid, &process)) {
        std::cerr << "Failed to find process with PID: " << selected_pid << std::endl;
        return 1;
    }

    ShowMainMenu(process);

    return 0;
}