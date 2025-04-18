#include "utils.h"
#include "disasm.h"
#include "watcher.h"

/**
 * Parse a signature string into a format that libmem can understand.
 * Handles formats like "48 8D 64 24 ? C6 05" or "48 8D 64 24 ?? C6 05"
 * 
 * @param signature The signature string to parse
 * @return The cleaned signature string
 */
std::string parse_signature(const std::string& signature) {
    std::string cleaned_signature;
    std::istringstream iss(signature);
    std::string token;
    
    while (iss >> token) {
        // Skip empty tokens
        if (token.empty()) {
            continue;
        }
        
        // Handle wildcard characters
        if (token == "?" || token == "??" || token == "**") {
            cleaned_signature += "?";
        } else {
            // Assume it's a hex value
            cleaned_signature += token;
        }
        
        cleaned_signature += " ";
    }
    
    // Remove trailing space if exists
    if (!cleaned_signature.empty() && cleaned_signature.back() == ' ') {
        cleaned_signature.pop_back();
    }
    
    return cleaned_signature;
}

/**
 * Scan for a byte pattern in a module
 * 
 * @param process The process to scan
 * @param module The module to limit the scan to (null for all modules)
 * @param signature The signature string to search for
 * @return ScanResult containing the results of the scan
 */
SignatureScanResult scan_module_for_pattern(const libmem::Process& process, 
                                           const std::optional<libmem::Module>& module,
                                           const std::string& signature) {
    SignatureScanResult result;
    result.success = false;
    
    // Parse the signature
    std::string parsed_sig = parse_signature(signature);
    
    // Define scanning parameters based on the module
    libmem::Address start_addr;
    size_t scan_size;
    
    if (module.has_value()) {
        start_addr = module->base;
        scan_size = module->size;
    } else {
        // Scan first module if no module specified
        auto modules_opt = libmem::EnumModules(&process);
        if (!modules_opt.has_value() || modules_opt->empty()) {
            return result;
        }
        
        start_addr = modules_opt->front().base;
        scan_size = modules_opt->front().size;
    }
    
    // Perform the signature scan
    auto found_addr_opt = libmem::SigScan(&process, parsed_sig.c_str(), start_addr, scan_size);
    
    if (found_addr_opt.has_value()) {
        result.success = true;
        result.address = found_addr_opt.value();
        result.matches.push_back(found_addr_opt.value());
    }
    
    return result;
}

/**
 * Scan for an array of bytes in memory using a console interface
 * 
 * @param process The process to scan
 * @param module Optional module to limit the scan to
 */
void scan_for_bytes(const libmem::Process& process, const std::optional<libmem::Module>& module) {
    // Module information for display
    std::string module_info = module.has_value() ? 
        module->name + " (Base: 0x" + std::to_string(module->base) + ")" : 
        "All Modules";
    
    // Clear the screen
    #ifdef _WIN32
    system("cls");
    #else
    system("clear");
    #endif
    
    std::cout << "===== SCAN FOR BYTE PATTERN =====" << std::endl;
    std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
    std::cout << "Module: " << module_info << std::endl;
    std::cout << "=================================" << std::endl;
    std::cout << "Enter byte pattern (e.g., 48 8D 64 24 ? C6 05), or 'q' to cancel:" << std::endl;
    std::cout << "Use ? or ?? as wildcards for unknown bytes" << std::endl;
    std::cout << "> ";
    
    std::string signature_input;
    std::getline(std::cin, signature_input);
    
    if (signature_input == "q" || signature_input == "Q") {
        return;
    }
    
    if (signature_input.empty()) {
        std::cout << "Empty pattern. Press Enter to return...";
        std::cin.ignore();
        return;
    }
    
    std::cout << "Scanning for pattern: " << signature_input << "..." << std::endl;
    
    // Perform the scan
    SignatureScanResult scan_result = scan_module_for_pattern(process, module, signature_input);
    
    if (scan_result.success) {
        std::cout << "Found pattern at address: 0x" << std::hex << scan_result.address << std::dec << std::endl;
        
        // Ask user what to do with the result
        std::cout << "=================================" << std::endl;
        std::cout << "1. Disassemble at match location" << std::endl;
        std::cout << "2. Watch memory at match location" << std::endl;
        std::cout << "3. Return to previous menu" << std::endl;
        std::cout << "Enter your choice: ";
        
        std::string choice;
        std::getline(std::cin, choice);
        
        if (choice == "1") {
            // Disassemble memory at the found address
            disassemble_memory_region(process, scan_result.address);
        } else if (choice == "2") {
            // Watch memory at the found address (monitoring 16 bytes by default)
            watch_memory_region(process, scan_result.address, 16);
        }
    } else {
        std::cout << "Pattern not found." << std::endl;
        std::cout << "Press Enter to return...";
        std::cin.ignore();
    }
}

/**
 * Find bytes in process memory (alias for scan_for_bytes)
 * 
 * @param process The process to scan
 * @param module Optional module to limit the scan to
 */
void find_bytes(const libmem::Process& process, const std::optional<libmem::Module>& module) {
    scan_for_bytes(process, module);
}
