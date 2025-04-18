#include "utils.h"

/**
 * Disassemble memory around a specific address using console output
 * 
 * @param process The process to disassemble from
 * @param address The address to disassemble around
 * @param instruction_count How many instructions to show
 * @return true if disassembly was completed successfully
 */
bool disassemble_memory_region(const libmem::Process& process, libmem::Address address, int instruction_count = 10) {
    // Clear the screen
    #ifdef _WIN32
    system("cls");
    #else
    system("clear");
    #endif
    
    std::cout << "===== MEMORY DISASSEMBLY =====" << std::endl;
    std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
    std::cout << "Disassembling memory at address: 0x" << std::hex << address << std::dec << std::endl;
    std::cout << "============================" << std::endl;
    
    bool disasm_success = false;
    
    // Buffer for reading memory to verify it's accessible
    std::vector<uint8_t> mem_buffer(128, 0); // Larger buffer to capture more instructions
    size_t bytes_read = libmem::ReadMemory(&process, address, mem_buffer.data(), mem_buffer.size());
    
    if (bytes_read < 16) { // Need at least a few bytes for meaningful disassembly
        std::cout << "Error: Memory at address 0x" << std::hex << address << std::dec << " is not accessible." << std::endl;
        std::cout << "Failed to access memory at target address" << std::endl;
    } else {
        // Show memory preview
        std::cout << "Memory preview at target address: ";
        for (size_t i = 0; i < std::min<size_t>(16, bytes_read); i++) {
            char hex_buff[4];
            snprintf(hex_buff, sizeof(hex_buff), "%02X ", mem_buffer[i]);
            std::cout << hex_buff;
            if ((i + 1) % 8 == 0) std::cout << " ";
        }
        std::cout << std::endl << std::endl;
        
        // Since we can't directly disassemble from process memory, we'll use a workaround:
        // 1. Read chunks of memory into our buffer
        // 2. Try manual disassembly by passing different offsets into the buffer to the disassembler
        
        libmem::Address current_addr = address;
        int instructions_found = 0;
        
        // Get architecture for proper disassembly
        libmem::Arch arch = libmem::GetArchitecture();
        
        // Create a new buffer that we'll use to simulate different memory locations
        // Transfer data from mem_buffer to this new buffer for disassembly
        std::vector<uint8_t> disasm_buffer(16, 0);
        
        while (instructions_found < instruction_count) {
            // Calculate offset into our memory buffer
            size_t offset = current_addr - address;
            
            // If we've gone beyond what we read, we need to stop
            if (offset >= bytes_read) {
                std::cout << "Reached end of readable memory." << std::endl;
                break;
            }
            
            // Copy a chunk from our memory buffer to the disassembly buffer
            size_t bytes_to_copy = std::min<size_t>(16, bytes_read - offset);
            std::copy(mem_buffer.data() + offset, mem_buffer.data() + offset + bytes_to_copy, disasm_buffer.data());
            
            // Try to disassemble this chunk as a single instruction
            auto disasm_result = libmem::Disassemble(
                reinterpret_cast<libmem::Address>(disasm_buffer.data()),
                arch,
                bytes_to_copy,
                1,  // instruction count = 1
                current_addr  // use original address for display
            );
            
            if (!disasm_result.has_value() || disasm_result->empty()) {
                std::cout << "Failed to disassemble at 0x" << std::hex << current_addr << std::dec << std::endl;
                
                // Move forward by one byte and try again
                current_addr += 1;
                continue;
            }
            
            // Get the instruction
            const auto& inst = disasm_result->front();
            
            // Format instruction for display
            std::cout << "0x" << std::hex << current_addr << std::dec << ": " 
                      << inst.mnemonic << " " << inst.op_str;
            
            // Add the bytes in hex format
            std::cout << " -> [ ";
            for (size_t i = 0; i < inst.bytes.size(); i++) {
                char hex_buff[4];
                snprintf(hex_buff, sizeof(hex_buff), "%02X ", inst.bytes[i]);
                std::cout << hex_buff;
            }
            std::cout << "]" << std::endl;
            
            // Check if this is a return instruction
            if (inst.mnemonic.find("ret") != std::string::npos) {
                std::cout << "Found return instruction, stopping disassembly." << std::endl;
                break;
            }
            
            // Move to next instruction
            current_addr += inst.bytes.size();
            instructions_found++;
        }
        
        if (instructions_found == 0) {
            std::cout << "Failed to disassemble any instructions." << std::endl;
        } else {
            disasm_success = true;
            std::cout << "\nDisassembly completed successfully" << std::endl;
        }
    }
    
    std::cout << "\nPress Enter to return to previous screen...";
    std::cin.ignore();
    
    return disasm_success;
}
