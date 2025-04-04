#ifdef _WIN32
#include "LIBMEMWIN/includeWIN/libmem/libmem.h"
#else
#include "LIBMEMLIN/includeLIN/libmem/libmem.h"
#endif

#include <iostream>
#include <string>
#include <map>

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

    std::cout << "Listing all modules in process: " << process.name << "\n";

    // List all modules
    std::map<std::string, lm_module_t> module_map;
    LM_EnumModulesEx(&process, [](lm_module_t* module, lm_void_t* arg) {
        auto* module_map = static_cast<std::map<std::string, lm_module_t>*>(arg);
        (*module_map)[module->name] = *module;
        std::cout << "Module Name: " << module->name << "\n";
        return LM_TRUE; // Continue enumeration
    }, &module_map);

    // Prompt the user to select a module or type "all"
    std::string module_name;
    std::cout << "Enter the module name to scan (or type 'all' to scan all modules): ";
    std::cin.ignore(); // Clear the input buffer
    std::getline(std::cin, module_name);

    // Signature to scan for
    std::string signatureREAL = "48 8D 64 24 ? C6 05 ? ? ? ? ? 4C 8D 05";
    std::string signature = "90"; //for testing purposes
    if (module_name == "all") {
        // Scan all modules
        for (const auto& pair : module_map) {
            const std::string& name = pair.first;
            const lm_module_t& module = pair.second;
            PerformSignatureScan(&process, const_cast<lm_module_t*>(&module), signature);
        }
    } else {
        // Scan the selected module
        if (module_map.find(module_name) != module_map.end()) {
            PerformSignatureScan(&process, const_cast<lm_module_t*>(&module_map[module_name]), signature);
        } else {
            std::cerr << "Invalid module name: " << module_name << "\n";
            return 1;
        }
    }

    return 0;
}