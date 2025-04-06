#ifdef _WIN32
#include "LIBMEMWIN/includeWIN/libmem/libmem.h"
#else
#include "LIBMEMLIN/includeLIN/libmem/libmem.h"
#endif

#include <iostream>
#include <string>
#include <map>

// Define a single global signature variable
const std::string GLOBAL_SIGNATURE = "48 8D 64 24 ? C6 05 ? ? ? ? ? 4C 8D 05";

// Callback function to list processes and store them in a map
lm_bool_t ListProcessesCallback(lm_process_t* process, lm_void_t* arg) {
    auto* process_map = static_cast<std::map<lm_pid_t, std::string>*>(arg);
    (*process_map)[process->pid] = process->name;
    std::cout << "[" << process->pid << "] " << process->name << "\n";
    return LM_TRUE; // Continue enumeration
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
        std::cout << "Signature found in module " << module->name << " at address: " << std::hex << result << "\n";
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

    HandleModuleListingAndScanning(process);

    return 0;
}