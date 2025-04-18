#include "utils.h"

/**
 * Continuously watch a memory region and display its value in various formats
 * With additional features to freeze and change values
 * 
 * @param process The process to read memory from
 * @param address The address to monitor
 * @param size The size of the memory region to monitor (defaults to 16 bytes)
 * @return true if watching was completed successfully
 */
bool watch_memory_region(const libmem::Process& process, libmem::Address address, size_t size = 16) {
    // Memory buffers
    std::vector<uint8_t> memory_buffer(size, 0);
    std::vector<uint8_t> frozen_buffer(size, 0);
    bool read_success = false;
    bool freeze_value = false;
    bool quit_requested = false;
    
    // Status variables
    std::string status_message = "Watching memory at address: 0x" + std::to_string(address);
    
    // Start the watching loop
    while (!quit_requested) {
        // Clear the screen each update
        #ifdef _WIN32
        system("cls");
        #else
        system("clear");
        #endif
        
        // Read and update memory display
        if (!freeze_value) {
            // Read from process memory
            size_t bytes_read = libmem::ReadMemory(&process, address, memory_buffer.data(), size);
            read_success = (bytes_read == size);
        } else if (freeze_value && !frozen_buffer.empty()) {
            // Write the frozen value back to memory to maintain the freeze
            libmem::WriteMemory(&process, address, frozen_buffer.data(), size);
            
            // Verify the frozen value was written by reading back
            size_t bytes_read = libmem::ReadMemory(&process, address, memory_buffer.data(), size);
            read_success = (bytes_read == size);
            
            // Use frozen buffer for display
            memory_buffer = frozen_buffer;
        }
        
        // Display the header
        std::cout << "===== MEMORY WATCHER =====" << std::endl;
        std::cout << "Process: " << process.name << " (PID: " << process.pid << ")" << std::endl;
        std::cout << "Address: 0x" << std::hex << address << std::dec << " (Size: " << size << " bytes)" << std::endl;
        std::cout << "Status: " << status_message << std::endl;
        if (freeze_value) {
            std::cout << "[FROZEN]" << std::endl;
        }
        std::cout << "=========================" << std::endl;
        
        if (read_success) {
            // Display memory in different formats
            
            // Hex display
            std::cout << "HEX: ";
            for (size_t i = 0; i < size; i++) {
                char hex_buff[4];
                snprintf(hex_buff, sizeof(hex_buff), "%02X ", memory_buffer[i]);
                std::cout << hex_buff;
                if ((i + 1) % 8 == 0) std::cout << " ";
            }
            std::cout << std::endl;
            
            // Integer display
            if (size >= 4) {
                std::cout << "INT32: " << *reinterpret_cast<int32_t*>(memory_buffer.data()) << std::endl;
                std::cout << "UINT32: " << *reinterpret_cast<uint32_t*>(memory_buffer.data()) << std::endl;
            }
            
            // Float display
            if (size >= 4) {
                std::cout << "FLOAT: " << *reinterpret_cast<float*>(memory_buffer.data()) << std::endl;
            }
            
            // Double display
            if (size >= 8) {
                std::cout << "DOUBLE: " << *reinterpret_cast<double*>(memory_buffer.data()) << std::endl;
            }
            
            // String display
            std::cout << "ASCII: ";
            for (size_t i = 0; i < size; i++) {
                char c = memory_buffer[i];
                std::cout << (c >= 32 && c <= 126 ? c : '.');
            }
            std::cout << std::endl;
        } else {
            std::cout << "Failed to read memory at address 0x" << std::hex << address << std::dec << std::endl;
        }
        
        // Display menu options
        std::cout << "=========================" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "f - " << (freeze_value ? "Unfreeze value" : "Freeze value") << std::endl;
        std::cout << "c - Change value" << std::endl;
        std::cout << "q - Quit" << std::endl;
        std::cout << "=========================" << std::endl;
        std::cout << "Enter command: ";
        
        std::string command;
        std::getline(std::cin, command);
        
        if (command == "q" || command == "Q") {
            quit_requested = true;
        } else if (command == "f" || command == "F") {
            // Toggle freeze state
            if (!freeze_value) {
                frozen_buffer = memory_buffer;
                freeze_value = true;
                status_message = "Value frozen";
            } else {
                freeze_value = false;
                status_message = "Value unfrozen";
            }
        } else if (command == "c" || command == "C") {
            // Change value menu
            #ifdef _WIN32
            system("cls");
            #else
            system("clear");
            #endif
            
            std::cout << "===== CHANGE VALUE =====" << std::endl;
            std::cout << "Select value type to change:" << std::endl;
            std::cout << "1. Int32" << std::endl;
            std::cout << "2. UInt32" << std::endl;
            std::cout << "3. Float" << std::endl;
            std::cout << "4. Double" << std::endl;
            std::cout << "5. Hex" << std::endl;
            std::cout << "6. Cancel" << std::endl;
            std::cout << "Enter choice: ";
            
            std::string type_choice_str;
            std::getline(std::cin, type_choice_str);
            int type_choice = 0;
            
            try {
                type_choice = std::stoi(type_choice_str);
            } catch (...) {
                status_message = "Invalid choice";
                continue;
            }
            
            if (type_choice >= 1 && type_choice <= 5) {
                std::cout << "Enter new value: ";
                std::string input_value;
                std::getline(std::cin, input_value);
                
                bool success = false;
                std::vector<uint8_t> new_value(size, 0);
                
                try {
                    if (type_choice == 1 && size >= 4) { // Int32
                        int32_t val = std::stoi(input_value);
                        *reinterpret_cast<int32_t*>(new_value.data()) = val;
                        success = true;
                    } else if (type_choice == 2 && size >= 4) { // UInt32
                        uint32_t val = static_cast<uint32_t>(std::stoul(input_value));
                        *reinterpret_cast<uint32_t*>(new_value.data()) = val;
                        success = true;
                    } else if (type_choice == 3 && size >= 4) { // Float
                        float val = std::stof(input_value);
                        *reinterpret_cast<float*>(new_value.data()) = val;
                        success = true;
                    } else if (type_choice == 4 && size >= 8) { // Double
                        double val = std::stod(input_value);
                        *reinterpret_cast<double*>(new_value.data()) = val;
                        success = true;
                    } else if (type_choice == 5) { // Hex
                        std::istringstream iss(input_value);
                        std::string byte_str;
                        size_t byte_idx = 0;
                        
                        while (iss >> byte_str && byte_idx < size) {
                            try {
                                uint8_t byte_val = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                                new_value[byte_idx++] = byte_val;
                                success = true;
                            } catch (...) {
                                success = false;
                                break;
                            }
                        }
                    }
                    
                    if (success) {
                        // Apply the change
                        if (freeze_value) {
                            // Update the frozen buffer
                            frozen_buffer = new_value;
                            status_message = "Value changed and frozen";
                        } else {
                            // Write directly to memory
                            size_t bytes_written = libmem::WriteMemory(&process, address, new_value.data(), size);
                            success = (bytes_written == size);
                            status_message = success ? "Value changed successfully" : "Failed to change value";
                        }
                    } else {
                        status_message = "Invalid value format or type";
                    }
                } catch (const std::exception& e) {
                    status_message = "Error changing value: " + std::string(e.what());
                }
            }
        }
    }
    
    std::cout << "Memory watching ended." << std::endl;
    return read_success;
}