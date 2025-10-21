#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>                    // for setw, setfill
#include <chrono>                     // for milliseconds
#include <thread>                     // for sleep_for
#include <atomic>                     // for atomic
#include <optional>                   // for std::optional
#include <cstring>                    // for memcpy
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/loop.hpp>  // Add this include for Loop class
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/component/animation.hpp>  // Add this for animation
#ifdef _WIN32
    #include "LIBMEMWIN/includeWIN/libmem/libmem.hpp"
#else
    #include "LIBMEMLIN/includeLIN/libmem/libmem.hpp"
#endif

using namespace ftxui;
#include <functional>  // for function
#include <memory>      // for allocator, __shared_ptr_access
#include <string>      // for string, basic_string, operator+, to_string
#include <vector>      // for vector

#include "ftxui/component/captured_mouse.hpp"  // for ftxui
#include "ftxui/component/component.hpp"       // for Menu, Horizontal, Renderer
#include "ftxui/component/component_base.hpp"  // for ComponentBase
#include "ftxui/component/component_options.hpp"  // for MenuOption
#include "ftxui/component/screen_interactive.hpp"  // for Component, ScreenInteractive
#include "ftxui/dom/elements.hpp"  // for text, separator, bold, hcenter, vbox, hbox, gauge, Element, operator|, border

// Structure to hold process information
struct ProcessInfo {
    std::string name;
    int pid;
    float cpu_usage;
    int memory_mb;
};

// Structure to hold module information
struct ModuleInfo {
    std::string name;
    std::string base_address;
    int size_kb;
};

// Structure to hold a disassembly instruction
struct AsmInstruction {
    uint64_t address;
    std::string bytes;
    std::string mnemonic;
    std::string operands;
};

/**
 * Result from module selection 
 */
struct ModuleSelectionResult {
    bool success = false;
    bool back_to_process_list = false;
    bool select_all_modules = false;
    std::vector<libmem::Module> all_modules;
    
    // Optional selected module - only valid when success is true and select_all_modules is false
    std::optional<libmem::Module> selected_module = std::nullopt;
};

/**
 * Result from process action selection
 */
enum class ProcessAction {
    SCAN_BYTES,
    ENTER_ADDRESS,
    BACK_TO_MODULES,
    CANCEL
};

/**
 * Result from signature scan
 */
struct SignatureScanResult {
    bool success = false;
    libmem::Address address = 0;
    std::vector<libmem::Address> matches;
};

// Helper function to convert a process to a display string
std::string ProcessToString(const ProcessInfo& process) {
    return process.name + " (PID: " + std::to_string(process.pid) + ")";
}

// Helper function to check if a string contains another string (case insensitive)
bool ContainsIgnoreCase(const std::string& str, const std::string& substr) {
    auto it = std::search(
        str.begin(), str.end(),
        substr.begin(), substr.end(),
        [](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); }
    );
    return it != str.end();
}

// Helper function to format number as hex with leading zeros
std::string FormatAsHex(uint64_t value, int width = 8) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(width) << std::hex << value;
    return ss.str();
}

// Helper function to format bytes as hex
std::string FormatHexBytes(uint64_t value, int numBytes) {
    std::stringstream ss;
    for (int i = 0; i < numBytes; i++) {
        if (i > 0) ss << " ";
        uint8_t byte = (value >> (i * 8)) & 0xFF;
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(byte);
    }
    return ss.str();
}

// Helper function to format value as ASCII characters
std::string FormatAsAscii(uint64_t value, int numBytes) {
    std::string result;
    for (int i = 0; i < numBytes; i++) {
        uint8_t byte = (value >> (i * 8)) & 0xFF;
        // Replace non-printable characters with dots
        result += (byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.';
    }
    return result;
}

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

// ========================== Memory Manipulation Functions ==========================

/**
 * Helper function to update memory display lines
 */
void updateMemoryDisplay(std::vector<std::string>& memory_lines, const std::vector<uint8_t>& buffer, libmem::Address base_address, size_t size) {
    memory_lines.clear();
    const int bytes_per_row = 16;
    
    for (size_t offset = 0; offset < size; offset += bytes_per_row) {
        libmem::Address row_addr = base_address + offset;
        size_t row_size = std::min(size_t(bytes_per_row), size - offset);
        
        std::stringstream ss;
        ss << FormatAsHex(row_addr, 16) << ": ";
        
        // Hex bytes
        for (size_t i = 0; i < row_size; i++) {
            ss << std::setfill('0') << std::setw(2) << std::hex << (int)buffer[offset + i] << " ";
            if (i == 7) ss << " "; // Extra space after 8 bytes
        }
        
        // Pad with spaces if row is incomplete
        for (size_t i = row_size; i < bytes_per_row; i++) {
            ss << "   ";
            if (i == 7) ss << " ";
        }
        
        ss << " | ";
        
        // ASCII representation
        for (size_t i = 0; i < row_size; i++) {
            char c = buffer[offset + i];
            ss << (c >= 32 && c <= 126 ? c : '.');
        }
        
        memory_lines.push_back(ss.str());
    }
}

/**
 * Disassembles memory at the specified address
 * 
 * @param process The target process
 * @param address The starting address to disassemble
 * @param instruction_count Number of instructions to disassemble
 * @return true if successful, false otherwise
 */
bool disassemble_memory_region(const libmem::Process& process, libmem::Address address, int instruction_count = 10) {
    // Setup UI components for disassembly view
    auto screen = ScreenInteractive::TerminalOutput();
    std::vector<std::string> disasm_lines;
    std::string status_message = "Disassembling memory...";
    int selected_index = 0;
    
    // Prepare component for disassembly display
    auto disasm_component = Menu(&disasm_lines, &selected_index);
    
    // Disassemble memory
    try {
        // Read memory from the process - use correct API with buffer
        std::vector<uint8_t> memory_buffer(128, 0); // Larger buffer to capture multiple instructions
        size_t bytes_read = libmem::ReadMemory(&process, address, memory_buffer.data(), memory_buffer.size());
        
        if (bytes_read < 16) { // Need at least a few bytes for meaningful disassembly
            status_message = "Failed to read memory at address " + FormatAsHex(address);
            disasm_lines.push_back("Error: Memory not accessible");
            disasm_lines.push_back("Address: " + FormatAsHex(address));
        } else {
            status_message = "Read " + std::to_string(bytes_read) + " bytes from memory";
            
            // Get architecture for proper disassembly
            libmem::Arch arch = libmem::GetArchitecture();
            
            libmem::Address current_addr = address;
            int instructions_found = 0;
            
            // Disassemble instruction by instruction
            while (instructions_found < instruction_count) {
                // Calculate offset into our memory buffer
                size_t offset = current_addr - address;
                
                // If we've gone beyond what we read, we need to stop
                if (offset >= bytes_read) {
                    disasm_lines.push_back("--- End of readable memory ---");
                    break;
                }
                
                // Prepare buffer for disassembly
                std::vector<uint8_t> disasm_buffer(16, 0);
                size_t bytes_to_copy = std::min<size_t>(16, bytes_read - offset);
                std::copy(memory_buffer.data() + offset, memory_buffer.data() + offset + bytes_to_copy, disasm_buffer.data());
                
                // Try to disassemble this chunk as a single instruction
                auto disasm_result = libmem::Disassemble(
                    reinterpret_cast<libmem::Address>(disasm_buffer.data()),
                    arch,
                    bytes_to_copy,
                    1,  // instruction count = 1
                    current_addr  // use original address for display
                );
                
                if (!disasm_result.has_value() || disasm_result->empty()) {
                    // Failed to disassemble, show raw bytes
                    std::stringstream ss;
                    ss << FormatAsHex(current_addr) << ": [Invalid] ";
                    for (size_t i = 0; i < std::min<size_t>(4, bytes_to_copy); i++) {
                        ss << std::setfill('0') << std::setw(2) << std::hex << (int)disasm_buffer[i] << " ";
                    }
                    disasm_lines.push_back(ss.str());
                    current_addr += 1; // Move forward by one byte
                    continue;
                }
                
                // Get the instruction
                const auto& inst = disasm_result->front();
                
                // Format instruction for display
                std::stringstream ss;
                ss << FormatAsHex(current_addr, 16) << ": ";
                
                // Add bytes in hex
                ss << "[ ";
                for (size_t i = 0; i < inst.bytes.size(); i++) {
                    ss << std::setfill('0') << std::setw(2) << std::hex << (int)inst.bytes[i] << " ";
                }
                ss << "] ";
                
                // Add mnemonic and operands
                ss << inst.mnemonic;
                if (!inst.op_str.empty()) {
                    ss << " " << inst.op_str;
                }
                
                disasm_lines.push_back(ss.str());
                
                // Check if this is a return instruction
                if (inst.mnemonic.find("ret") != std::string::npos) {
                    disasm_lines.push_back("--- Return instruction found ---");
                    break;
                }
                
                // Move to next instruction
                current_addr += inst.bytes.size();
                instructions_found++;
            }
            
            status_message = "Disassembled " + std::to_string(instructions_found) + " instructions";
        }
    } catch (const std::exception& e) {
        status_message = "Error: " + std::string(e.what());
        disasm_lines.push_back("Exception: " + std::string(e.what()));
    }
    
    // Create renderer for the disassembly view
    auto renderer = Renderer(disasm_component, [&] {
        return vbox({
            text("Disassembly of " + FormatAsHex(address)) | bold,
            separator(),
            disasm_component->Render() | frame | size(HEIGHT, LESS_THAN, 20),
            separator(),
            text(status_message),
            text("Press ESC to return") | color(Color::GrayDark),
        });
    });
    
    // Add event handler
    auto component = CatchEvent(renderer, [&](Event event) {
        if (event == Event::Escape) {
            screen.Exit();
            return true;
        }
        return false;
    });
    
    // Run the UI loop
    screen.Loop(component);
    return !disasm_lines.empty();
}

/**
 * Watches a memory region for changes
 * 
 * @param process The target process
 * @param address The starting address to watch
 * @param size Size of the memory region in bytes
 * @return true if successful, false otherwise
 */
bool watch_memory_region(const libmem::Process& process, libmem::Address address, size_t size = 16) {
    // Setup UI components for memory watch
    auto screen = ScreenInteractive::TerminalOutput();
    std::vector<std::string> memory_lines;
    std::vector<uint8_t> memory_buffer(size, 0);
    std::vector<uint8_t> frozen_buffer(size, 0);
    std::string status_message = "Watching memory...";
    int selected_index = 0;
    bool is_running = true;
    bool paused = false;
    bool freeze_value = false;
    
    // Read initial memory values
    try {
        size_t bytes_read = libmem::ReadMemory(&process, address, memory_buffer.data(), size);
        
        if (bytes_read != size) {
            status_message = "Failed to read memory at address " + FormatAsHex(address) + " (read " + std::to_string(bytes_read) + "/" + std::to_string(size) + " bytes)";
            return false;
        }
        
        // Initialize frozen buffer
        frozen_buffer = memory_buffer;
        
        // Generate initial display
        updateMemoryDisplay(memory_lines, memory_buffer, address, size);
        
        status_message = "Successfully reading " + std::to_string(size) + " bytes from " + FormatAsHex(address);
    } catch (const std::exception& e) {
        status_message = "Error: " + std::string(e.what());
        return false;
    }
    
    // Prepare component for memory display
    auto menu_option = MenuOption();
    menu_option.on_change = [&] { 
        if (selected_index < memory_lines.size()) {
        status_message = "Selected: " + memory_lines[selected_index];
        }
    };
    
    auto memory_component = Menu(&memory_lines, &selected_index, menu_option);
    
    // Value type and edit features
    std::string edit_value;
    bool editing = false;
    int type_index = 0; // 0=int32, 1=uint32, 2=float, 3=double, 4=bytes
    std::vector<std::string> type_names = {"int32", "uint32", "float", "double", "bytes"};
    
    auto input_component = Input(&edit_value, "Enter new value");
    auto type_selector = Radiobox(&type_names, &type_index);
    
    // Function to apply value changes
    auto apply_value_change = [&](const std::string& input_value, int type_index) -> bool {
        if (input_value.empty()) {
            status_message = "No value entered";
            return false;
        }
        
        try {
            // Calculate byte offset for selected row
            size_t row_offset = (selected_index * 16) % size;
            std::vector<uint8_t> new_bytes = memory_buffer; // Copy current buffer
            
            // Convert based on type
            switch (type_index) {
                case 0: { // int32
                    int32_t int_val = std::stoi(input_value);
                    if (row_offset + sizeof(int32_t) <= size) {
                        std::memcpy(new_bytes.data() + row_offset, &int_val, sizeof(int32_t));
                    } else {
                        status_message = "Not enough space for int32";
                        return false;
                    }
                    break;
                }
                case 1: { // uint32
                    uint32_t uint_val = static_cast<uint32_t>(std::stoul(input_value));
                    if (row_offset + sizeof(uint32_t) <= size) {
                        std::memcpy(new_bytes.data() + row_offset, &uint_val, sizeof(uint32_t));
                    } else {
                        status_message = "Not enough space for uint32";
                        return false;
                    }
                    break;
                }
                case 2: { // float
                    float float_val = std::stof(input_value);
                    if (row_offset + sizeof(float) <= size) {
                        std::memcpy(new_bytes.data() + row_offset, &float_val, sizeof(float));
                    } else {
                        status_message = "Not enough space for float";
                        return false;
                    }
                    break;
                }
                case 3: { // double
                    double double_val = std::stod(input_value);
                    if (row_offset + sizeof(double) <= size) {
                        std::memcpy(new_bytes.data() + row_offset, &double_val, sizeof(double));
                    } else {
                        status_message = "Not enough space for double";
                        return false;
                    }
                    break;
                }
                case 4: { // bytes (format: "AA BB CC DD")
                    std::istringstream iss(input_value);
                    std::string byte_str;
                    size_t byte_index = 0;
                    
                    while (iss >> byte_str && byte_index < 16 && (row_offset + byte_index) < size) {
                        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                        new_bytes[row_offset + byte_index] = byte;
                        byte_index++;
                    }
                    break;
                }
            }
            
            // Apply the change - FIXED VERSION
            if (freeze_value) {
                // Update the frozen buffer and write it back to memory to maintain freeze
                frozen_buffer = new_bytes;
                memory_buffer = new_bytes; // Update display buffer
                updateMemoryDisplay(memory_lines, memory_buffer, address, size);
                
                // Write the frozen value back to memory to maintain the freeze
                size_t bytes_written = libmem::WriteMemory(&process, address, frozen_buffer.data(), size);
                if (bytes_written == size) {
                    status_message = "Value changed and frozen";
                } else {
                    status_message = "Failed to write frozen value";
                }
                return true;
            } else {
                // Write directly to memory
                size_t bytes_written = libmem::WriteMemory(&process, address, new_bytes.data(), size);
                
                if (bytes_written == size) {
                    memory_buffer = new_bytes; // Update our buffer
                    updateMemoryDisplay(memory_lines, memory_buffer, address, size);
                    status_message = "Value changed successfully";
                    return true;
                } else {
                    status_message = "Failed to write memory (wrote " + std::to_string(bytes_written) + "/" + std::to_string(size) + " bytes)";
                    return false;
                }
            }
        } catch (const std::exception& e) {
            status_message = "Error: " + std::string(e.what());
            return false;
        }
    };
    
    // Function to toggle freezing - FIXED VERSION
    auto toggle_freeze = [&]() {
        if (!freeze_value) {
            // Freeze current values
            frozen_buffer = memory_buffer;
            freeze_value = true;
            status_message = "Value frozen";
        } else {
            // Unfreeze values
            freeze_value = false;
            status_message = "Value unfrozen";
        }
    };
    
    // Update thread for real-time memory watching - FIXED VERSION
    std::atomic<bool> thread_running{true};
    std::thread update_thread([&]() {
        while (thread_running) {
            // Only update if not paused
            if (!paused && is_running) {
                try {
                    if (!freeze_value) {
                        // Read current memory values only when not frozen
                        std::vector<uint8_t> current_buffer(size, 0);
                        size_t bytes_read = libmem::ReadMemory(&process, address, current_buffer.data(), size);
                        
                        if (bytes_read == size) {
                            // Check for changes and update display
                            bool changed = false;
                            for (size_t i = 0; i < size; i++) {
                                if (current_buffer[i] != memory_buffer[i]) {
                                    changed = true;
                                    break;
                                }
                            }
                            
                            if (changed) {
                                memory_buffer = current_buffer;
                                updateMemoryDisplay(memory_lines, memory_buffer, address, size);
                            }
                        }
                    }
                    // When frozen, do nothing - just keep displaying frozen values
                } catch (...) {
                    // Ignore errors during update
                }
            }
            
            // Sleep to avoid excessive CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Reduced frequency
        }
    });
    
    // Create container for edit components
    auto edit_container = Container::Vertical({
        input_component,
        type_selector
    });
    
    // Main component structure
    auto container = Container::Vertical({
        memory_component,
        edit_container
    });
    container->SetActiveChild(memory_component);
    
    // Create renderer for the memory watch view
    auto renderer = Renderer(container, [&] {
        std::string title = "Memory Watch - " + FormatAsHex(address) + " (" + 
                          std::to_string(size) + " bytes)" + 
                          (paused ? " [PAUSED]" : "");
                          
        // Show edit components only when editing
        Elements edit_elements;
        if (editing) {
            edit_elements = {
                separator(),
                text("Edit Value as " + type_names[type_index]),
                hbox({
                    text("New value: "),
                    input_component->Render()
                }),
                type_selector->Render(),
                text("Press ENTER to apply, ESC to cancel") | color(Color::GrayDark)
            };
        }
        
        // Construct the elements in proper format for vbox
        Elements elements = {
            text(title) | bold,
            separator(),
            memory_component->Render() | frame | ftxui::size(HEIGHT, LESS_THAN, 20)
        };
        
        // Add edit elements if editing
        elements.insert(elements.end(), edit_elements.begin(), edit_elements.end());
        
        // Add the remaining elements
        elements.push_back(separator());
        elements.push_back(text(status_message));
        std::string freeze_status = freeze_value ? " [FROZEN]" : "";
        elements.push_back(text("Controls: (E)dit | (P)ause | (Z)Freeze" + freeze_status + " | (G)oto | (ESC)Return") | color(Color::GrayDark));
        
        return vbox(elements);
    });
    
    // Add event handler
    auto event_handler = CatchEvent(renderer, [&](Event event) {
        if (editing) {
            // Edit mode controls
            if (event == Event::Escape) {
                // Cancel editing
                editing = false;
                container->SetActiveChild(memory_component);
                edit_value = "";
                return true;
            } else if (event == Event::Return) {
                // Apply the edit
                if (apply_value_change(edit_value, type_index)) {
                    editing = false;
                    container->SetActiveChild(memory_component);
                    edit_value = "";
                }
                return true;
            }
            return false;
        } else {
            // Normal mode controls
            if (event == Event::Escape) {
                screen.Exit();
                return true;
            } else if (event == Event::Character('e') || event == Event::Character('E')) {
                // Enter edit mode
                editing = true;
                container->SetActiveChild(edit_container);
                
                // Prefill with current value based on type
                size_t row_offset = (selected_index * 16) % size;
                switch (type_index) {
                    case 0: { // int32
                        if (row_offset + sizeof(int32_t) <= size) {
                            int32_t int_val;
                            std::memcpy(&int_val, memory_buffer.data() + row_offset, sizeof(int32_t));
                            edit_value = std::to_string(int_val);
                        } else {
                            edit_value = "0";
                        }
                        break;
                    }
                    case 1: { // uint32
                        if (row_offset + sizeof(uint32_t) <= size) {
                            uint32_t uint_val;
                            std::memcpy(&uint_val, memory_buffer.data() + row_offset, sizeof(uint32_t));
                            edit_value = std::to_string(uint_val);
                        } else {
                            edit_value = "0";
                        }
                        break;
                    }
                    case 2: { // float
                        if (row_offset + sizeof(float) <= size) {
                        float float_val;
                            std::memcpy(&float_val, memory_buffer.data() + row_offset, sizeof(float));
                        edit_value = std::to_string(float_val);
                        } else {
                            edit_value = "0.0";
                        }
                        break;
                    }
                    case 3: { // double
                        if (row_offset + sizeof(double) <= size) {
                        double double_val;
                            std::memcpy(&double_val, memory_buffer.data() + row_offset, sizeof(double));
                        edit_value = std::to_string(double_val);
                        } else {
                            edit_value = "0.0";
                        }
                        break;
                    }
                    case 4: { // bytes
                        std::stringstream ss;
                        for (size_t i = 0; i < std::min(size_t(16), size - row_offset); i++) {
                            if (i > 0) ss << " ";
                            ss << std::setfill('0') << std::setw(2) << std::hex << (int)memory_buffer[row_offset + i];
                        }
                        edit_value = ss.str();
                        break;
                    }
                }
                
                return true;
            } else if (event == Event::Character('p') || event == Event::Character('P')) {
                // Toggle pause
                paused = !paused;
                status_message = paused ? "Watching paused" : "Watching resumed";
                return true;
            } else if (event == Event::Character('z') || event == Event::Character('Z')) {
                // Toggle freeze with Z key (instead of F which conflicts with Filter)
                toggle_freeze();
                return true;
            } else if (event == Event::Character('g') || event == Event::Character('G')) {
                // Go to address - simple implementation
                status_message = "Go to address feature - enter address in hex (e.g., 0x12345678)";
                return true;
            }
            return false;
        }
    });
    
    // Run the UI loop
    screen.Loop(event_handler);
    
    // Cleanup
    thread_running = false;
    if (update_thread.joinable()) {
        update_thread.join();
    }
    
    return true;
}

/**
 * Scan a module for a pattern/signature
 * 
 * @param process The target process
 * @param module Optional module to limit scan to (nullptr for entire process)
 * @param signature The signature to scan for
 * @return Result of the scan operation
 */
SignatureScanResult scan_module_for_pattern(const libmem::Process& process, 
                                       const std::optional<libmem::Module>& module,
                                       const std::string& signature) {
    SignatureScanResult result;
    result.success = false;
    
    // Parse the signature
    std::string cleaned_signature = parse_signature(signature);
    if (cleaned_signature.empty()) {
        return result;
    }
    
    try {
        // Determine scan region
        libmem::Address start_address = 0;
        size_t scan_size = 0;
        
        if (module.has_value()) {
            // Scan specific module
            start_address = module->base;
            scan_size = module->size;
        } else {
            // Scan first module if no module specified
            auto modules_opt = libmem::EnumModules(&process);
            if (!modules_opt.has_value() || modules_opt->empty()) {
            return result;
            }
            
            start_address = modules_opt->front().base;
            scan_size = modules_opt->front().size;
        }
        
        // Perform the signature scan using the correct API
        auto result_opt = libmem::SigScan(&process, cleaned_signature.c_str(), start_address, scan_size);
        
        if (result_opt.has_value()) {
            result.success = true;
            result.address = result_opt.value();
            result.matches.push_back(result_opt.value()); // Add the match
        }
    } catch (const std::exception& e) {
        // Handle exceptions - log the error for debugging
        std::cerr << "Scan error: " << e.what() << std::endl;
        result.success = false;
    }
    
    return result;
}

// Generate fake assembly instructions for display
std::vector<AsmInstruction> GenerateFakeDisassembly(uint64_t baseAddress, uint64_t counter) {
    // Common x86_64 instructions
    const std::vector<std::pair<std::string, std::string>> instructions = {
        {"mov", "rax, [rbp-0x8]"},
        {"push", "rbx"},
        {"pop", "rcx"},
        {"add", "rax, rbx"},
        {"sub", "rcx, 0x10"},
        {"xor", "rdx, rdx"},
        {"call", "0x12345678"},
        {"jmp", "0x87654321"},
        {"cmp", "rax, 0x1"},
        {"je", FormatAsHex(baseAddress + 0x20)},
        {"lea", "rsi, [rip+0x1234]"},
        {"ret", ""},
    };
    
    std::vector<AsmInstruction> result;
    
    // Use counter to add some variation
    uint64_t seed = counter % 12;
    
    for (int i = 0; i < 10; i++) {
        int idx = (seed + i) % instructions.size();
        auto& [mnemonic, operands] = instructions[idx];
        
        uint64_t address = baseAddress + (i * 4);
        std::string bytes = FormatHexBytes(address + counter, 4);
        
        result.push_back({address, bytes, mnemonic, operands});
    }
    
    return result;
}

int main() {
  using namespace ftxui;
  
  // Create a fullscreen interface
  auto screen = ScreenInteractive::Fullscreen();

  // Active panel tracking for navigation
  enum class ActivePanel {
    PROCESSES,
    MODULES,
    MEMORY,
    DISASSEMBLY
  };

  ActivePanel active_panel = ActivePanel::PROCESSES;

  // Real process list from libmem
  std::vector<ProcessInfo> all_processes;
  std::vector<libmem::Process> libmem_processes;
  
  auto processes_opt = libmem::EnumProcesses();
  if (processes_opt.has_value()) {
      libmem_processes = processes_opt.value();
      
      // Convert libmem::Process to ProcessInfo for display
      for (const auto& proc : libmem_processes) {
          ProcessInfo info;
          info.name = proc.name;
          info.pid = proc.pid;
          info.cpu_usage = 0.0f; // CPU usage not available in libmem
          info.memory_mb = 0;    // Memory usage not available in libmem
          all_processes.push_back(info);
      }
  }

  // Module list - will be populated when a process is selected
  std::vector<ModuleInfo> all_modules;
  std::vector<libmem::Module> libmem_modules;
  std::optional<libmem::Process> selected_process;

  // Filtered copies that will be shown in menu
  std::vector<ProcessInfo> filtered_processes = all_processes;
  std::vector<ModuleInfo> filtered_modules = all_modules;

  // Convert to menu entries
  std::vector<std::string> process_entries;
  for (const auto& process : filtered_processes) {
      process_entries.push_back(ProcessToString(process));
  }

  std::vector<std::string> module_entries;
  for (const auto& module : filtered_modules) {
      module_entries.push_back(module.name);
  }

  // Filter input variables
  std::string process_filter = "";
  std::string module_filter = "";
  std::string signature_input = "";
  std::string address_input = "";

  // Menu selection variables
  int process_selected = 0;
  int module_selected = 0;
  bool show_process_filter = false;
  bool show_module_filter = false;
  bool show_signature_dialog = false;
  bool show_address_dialog = false;

  // Memory and disassembly selection
  int memory_selected = 0;
  int disasm_selected = 0;

  // Memory viewer state
  libmem::Address current_memory_address = 0;
  int memory_scroll_offset = 0;

  // Status message
  std::string status_message = "Select a process to begin";

  // Menu options
  auto menu_option = MenuOption::Vertical();
  menu_option.entries_option.transform = [](EntryState state) {
    Element e = text(state.label);
    if (state.focused) {
      e = e | bgcolor(Color::Blue);
    }
    if (state.active) {
      e = e | bold;
    }
    return e;
  };
  
  auto module_menu_option = MenuOption::Vertical();
  module_menu_option.entries_option.transform = [](EntryState state) {
    Element e = text(state.label);
    if (state.focused) {
      e = e | bgcolor(Color::Cyan);
    }
    if (state.active) {
      e = e | bold;
    }
    return e;
  };
  
  auto memory_menu_option = MenuOption::Vertical();
  memory_menu_option.entries_option.transform = [](EntryState state) {
    Element e = text(state.label);
    if (state.focused) {
      e = e | bgcolor(Color::Green);
    }
    if (state.active) {
      e = e | bold;
    }
    return e;
  };
  
  auto disasm_menu_option = MenuOption::Vertical();
  disasm_menu_option.entries_option.transform = [](EntryState state) {
    Element e = text(state.label);
    if (state.focused) {
      e = e | bgcolor(Color::Yellow);
    }
    if (state.active) {
      e = e | bold;
    }
    return e;
  };

  // Function to apply process filter
  auto apply_process_filter = [&]() {
    filtered_processes.clear();
    process_entries.clear();
    
    // If filter is empty, show all processes
    if (process_filter.empty()) {
      filtered_processes = all_processes;
    } else {
      // Otherwise, filter processes
      for (const auto& process : all_processes) {
        if (ContainsIgnoreCase(process.name, process_filter) || 
            ContainsIgnoreCase(std::to_string(process.pid), process_filter)) {
          filtered_processes.push_back(process);
        }
      }
    }
    
    // Update process entries
    for (const auto& process : filtered_processes) {
      process_entries.push_back(ProcessToString(process));
    }
    
    // Reset selection if out of bounds
    if (process_selected >= static_cast<int>(process_entries.size())) {
      process_selected = process_entries.empty() ? 0 : process_entries.size() - 1;
    }
  };

  // Function to apply module filter
  auto apply_module_filter = [&]() {
    filtered_modules.clear();
    module_entries.clear();
    
    // If filter is empty, show all modules
    if (module_filter.empty()) {
      filtered_modules = all_modules;
    } else {
      // Otherwise, filter modules
      for (const auto& module : all_modules) {
        if (ContainsIgnoreCase(module.name, module_filter)) {
          filtered_modules.push_back(module);
        }
      }
    }
    
    // Update module entries
    for (const auto& module : filtered_modules) {
      module_entries.push_back(module.name);
    }
    
    // Reset selection if out of bounds
    if (module_selected >= static_cast<int>(module_entries.size())) {
      module_selected = module_entries.empty() ? 0 : module_entries.size() - 1;
    }
  };

  // Input components for filtering and dialogs
  Component process_filter_input = Input(&process_filter, "Filter processes...");
  Component module_filter_input = Input(&module_filter, "Filter modules...");
  Component signature_input_component = Input(&signature_input, "Enter signature (e.g., 48 8D 64 24 ? C6 05)");
  Component address_input_component = Input(&address_input, "Enter address (hex, e.g., 0x12345678)");

  // Attach filter callbacks
  auto process_input_with_filter = [&](Component c) {
    return Renderer(c, [&, c] {
      if (show_process_filter) {
        apply_process_filter();
      }
      return c->Render();
    });
  };

  auto module_input_with_filter = [&](Component c) {
    return Renderer(c, [&, c] {
      if (show_module_filter) {
        apply_module_filter();
      }
      return c->Render();
    });
  };

  process_filter_input = process_input_with_filter(process_filter_input);
  module_filter_input = module_input_with_filter(module_filter_input);

  // Create menus
  Component process_menu = Menu(&process_entries, &process_selected, menu_option);
  Component module_menu = Menu(&module_entries, &module_selected, module_menu_option);

  // Memory and Disassembly menus - updated in the renderer
  std::vector<std::string> memory_entries;
  std::vector<std::string> disasm_entries;
  Component memory_menu = Menu(&memory_entries, &memory_selected, memory_menu_option);
  Component disasm_menu = Menu(&disasm_entries, &disasm_selected, disasm_menu_option);

  // Create tab container for navigation between filter input and list
  auto process_container = Container::Vertical({
    process_filter_input,
    process_menu
  });

  auto module_container = Container::Vertical({
    module_filter_input,
    module_menu
  });

  // By default, hide filter inputs
  process_container->SetActiveChild(process_menu);
  module_container->SetActiveChild(module_menu);

  // Main container - NO NESTING, just the 4 panels
  auto main_container = Container::Tab({
    process_container,
    module_container,
    memory_menu,
    disasm_menu
  }, (int*)&active_panel);

  // Create the component with event handling
  auto component = Renderer(main_container, [&] {
    // Process section with conditional filter display
    Element process_section;
    std::string process_title = show_process_filter ? "Filter Processes (ESC to close)" : "PROCESSES";
    if (active_panel == ActivePanel::PROCESSES) {
      process_title = "► " + process_title + " ◄";
    }

    if (show_process_filter) {
      process_section = vbox({
        text(process_title) | bold | color(active_panel == ActivePanel::PROCESSES ? Color::GreenLight : Color::White),
        separator(),
        process_filter_input->Render(),
        separator(),
        process_menu->Render() | vscroll_indicator | frame | flex,
      });
    } else {
      process_section = vbox({
        text(process_title) | bold | color(active_panel == ActivePanel::PROCESSES ? Color::GreenLight : Color::White),
        separator(),
        process_menu->Render() | vscroll_indicator | frame | flex,
      });
    }

    // Module section with conditional filter display
    Element module_section;
    std::string module_title = show_module_filter ? "Filter Modules (ESC to close)" : "MODULES";
    if (active_panel == ActivePanel::MODULES) {
      module_title = "► " + module_title + " ◄";
    }

    if (show_module_filter) {
      module_section = vbox({
        text(module_title) | bold | color(active_panel == ActivePanel::MODULES ? Color::CyanLight : Color::White),
        separator(),
        module_filter_input->Render(),
        separator(),
        module_menu->Render() | vscroll_indicator | frame | flex,
      });
    } else {
      module_section = vbox({
        text(module_title) | bold | color(active_panel == ActivePanel::MODULES ? Color::CyanLight : Color::White),
        separator(),
        module_menu->Render() | vscroll_indicator | frame | flex,
      });
    }

    // Get the selected process and module (if available)
    ProcessInfo selected_process_info;
    if (!filtered_processes.empty() && process_selected < static_cast<int>(filtered_processes.size())) {
      selected_process_info = filtered_processes[process_selected];
    } else {
      selected_process_info = {"No process selected", 0, 0.0, 0};
    }

    ModuleInfo selected_module;
    if (!filtered_modules.empty() && module_selected < static_cast<int>(filtered_modules.size())) {
      selected_module = filtered_modules[module_selected];
    } else {
      selected_module = {"No module selected", "0x00000000", 0};
    }

    // Update memory menu entries
    memory_entries.clear();

    // Memory title with active indicator and current address
    std::string memory_title = "MEMORY";
    if (active_panel == ActivePanel::MEMORY) {
      memory_title = "► " + memory_title + " ◄";
    }

    // Add current viewing address to title if we have a process
    if (selected_process.has_value() && !libmem_modules.empty()) {
      libmem::Address view_addr = 0;
      if (current_memory_address != 0) {
        view_addr = current_memory_address + (memory_scroll_offset * 16);
      } else if (module_selected >= 0 && module_selected < (int)libmem_modules.size()) {
        view_addr = libmem_modules[module_selected].base + (memory_scroll_offset * 16);
      } else {
        view_addr = libmem_modules[0].base + (memory_scroll_offset * 16);
      }

      std::stringstream ss;
      ss << " @ 0x" << std::hex << std::setfill('0') << std::setw(12) << view_addr;
      memory_title += ss.str();
    }

    // Only show memory if we have a selected process and modules
    if (selected_process.has_value() && !libmem_modules.empty()) {
        // Determine base address for memory display
        libmem::Address display_addr = 0;

        if (current_memory_address != 0) {
            // Use user-specified address
            display_addr = current_memory_address + (memory_scroll_offset * 16);
        } else if (module_selected >= 0 && module_selected < static_cast<int>(libmem_modules.size())) {
            // Use selected module's base address
            display_addr = libmem_modules[module_selected].base + (memory_scroll_offset * 16);
        } else {
            // Default to first module
            display_addr = libmem_modules[0].base + (memory_scroll_offset * 16);
        }

        // Display 100 rows of memory (16 bytes each = 1600 bytes total)
        for (int i = 0; i < 100; i++) {
            libmem::Address addr = display_addr + (i * 16);

            try {
                std::vector<uint8_t> buffer(16, 0);
                size_t bytes_read = libmem::ReadMemory(&selected_process.value(), addr, buffer.data(), 16);

                if (bytes_read > 0) {
                    // Format address as hex
                    std::stringstream ss;
                    ss << std::hex << std::setfill('0') << std::setw(12) << addr << ": ";

                    // Hex bytes
                    for (size_t j = 0; j < 16; j++) {
                        if (j < bytes_read) {
                            ss << std::hex << std::setfill('0') << std::setw(2) << (int)buffer[j] << " ";
                        } else {
                            ss << "?? ";
                        }
                        if (j == 7) ss << " "; // Extra space
                    }

                    ss << " │ ";

                    // ASCII representation
                    for (size_t j = 0; j < bytes_read && j < 16; j++) {
                        char c = buffer[j];
                        ss << (c >= 32 && c <= 126 ? c : '.');
                    }

                    memory_entries.push_back(ss.str());
                } else {
                    std::stringstream ss;
                    ss << std::hex << std::setfill('0') << std::setw(12) << addr << ": [Access Denied]";
                    memory_entries.push_back(ss.str());
                }
            } catch (const std::exception& e) {
                std::stringstream ss;
                ss << std::hex << std::setfill('0') << std::setw(12) << addr << ": [Error]";
                memory_entries.push_back(ss.str());
            }
        }
    } else {
        memory_entries.push_back("Select a process and module to view memory");
    }
    
    // Update disassembly menu entries
    disasm_entries.clear();

    // Disassembly title with active indicator
    std::string disasm_title = "DISASSEMBLY";
    if (active_panel == ActivePanel::DISASSEMBLY) {
      disasm_title = "► " + disasm_title + " ◄";
    }

    // Only show disassembly if we have a selected process and modules
    if (selected_process.has_value() && !libmem_modules.empty()) {
        // Disassemble at the selected memory address
        libmem::Address disasm_base = 0;

        // Calculate the address of the selected memory row
        if (memory_selected >= 0 && memory_selected < (int)memory_entries.size()) {
            // Use the same address calculation as the memory viewer
            libmem::Address display_addr = 0;
            if (current_memory_address != 0) {
                display_addr = current_memory_address + (memory_scroll_offset * 16);
            } else if (module_selected >= 0 && module_selected < (int)libmem_modules.size()) {
                display_addr = libmem_modules[module_selected].base + (memory_scroll_offset * 16);
            } else {
                display_addr = libmem_modules[0].base + (memory_scroll_offset * 16);
            }

            // Use the selected row's address
            disasm_base = display_addr + (memory_selected * 16);
        } else {
            // Fallback to module base if no memory selected
            disasm_base = libmem_modules[0].base;
        }

        // Add the disassembly address to the title
        std::stringstream ss;
        ss << " @ 0x" << std::hex << std::setfill('0') << std::setw(12) << disasm_base;
        disasm_title += ss.str();
        
        // Generate real disassembly for more instructions
        try {
            // Read more memory from the process for better context
            std::vector<uint8_t> memory_buffer(256, 0);
            size_t bytes_read = libmem::ReadMemory(&selected_process.value(), disasm_base, memory_buffer.data(), memory_buffer.size());

            if (bytes_read >= 16) {
                // Get architecture for proper disassembly
                libmem::Arch arch = libmem::GetArchitecture();

                libmem::Address current_addr = disasm_base;
                int instructions_found = 0;
                const int max_instructions = 30; // Show 30 instructions for better context
                
                // Disassemble instruction by instruction
                while (instructions_found < max_instructions) {
                    // Calculate offset into our memory buffer
                    size_t offset = current_addr - disasm_base;
                    
                    // If we've gone beyond what we read, we need to stop
                    if (offset >= bytes_read) {
                        break;
                    }
                    
                    // Prepare buffer for disassembly
                    std::vector<uint8_t> disasm_buffer(16, 0);
                    size_t bytes_to_copy = std::min<size_t>(16, bytes_read - offset);
                    std::copy(memory_buffer.data() + offset, memory_buffer.data() + offset + bytes_to_copy, disasm_buffer.data());
                    
                    // Try to disassemble this chunk as a single instruction
                    auto disasm_result = libmem::Disassemble(
                        reinterpret_cast<libmem::Address>(disasm_buffer.data()),
                        arch,
                        bytes_to_copy,
                        1,  // instruction count = 1
                        current_addr  // use original address for display
                    );
                    
                    if (!disasm_result.has_value() || disasm_result->empty()) {
                        // Failed to disassemble, show raw bytes
                        std::stringstream ss;
                        ss << FormatAsHex(current_addr, 16) << ": [Invalid] ";
                        for (size_t i = 0; i < std::min<size_t>(4, bytes_to_copy); i++) {
                            ss << std::setfill('0') << std::setw(2) << std::hex << (int)disasm_buffer[i] << " ";
                        }
                        disasm_entries.push_back(ss.str());
                        current_addr += 1; // Move forward by one byte
                        continue;
                    }
                    
                    // Get the instruction
                    const auto& inst = disasm_result->front();
                    
                    // Format instruction for display
                    std::stringstream ss;
                    ss << FormatAsHex(current_addr, 16) << ": ";
                    
                    // Add bytes in hex
                    ss << "[ ";
                    for (size_t i = 0; i < inst.bytes.size(); i++) {
                        ss << std::setfill('0') << std::setw(2) << std::hex << (int)inst.bytes[i] << " ";
                    }
                    ss << "] ";
                    
                    // Add mnemonic and operands
                    ss << inst.mnemonic;
                    if (!inst.op_str.empty()) {
                        ss << " " << inst.op_str;
                    }
                    
                    disasm_entries.push_back(ss.str());
                    
                    // Check if this is a return instruction
                    if (inst.mnemonic.find("ret") != std::string::npos) {
                        break;
                    }
                    
                    // Move to next instruction
                    current_addr += inst.bytes.size();
                    instructions_found++;
                }
            } else {
                disasm_entries.push_back("Failed to read memory from process");
            }
        } catch (const std::exception& e) {
            disasm_entries.push_back("Error: " + std::string(e.what()));
        }
    } else {
        disasm_entries.push_back("Select a process to view disassembly");
    }

    // Process and module info section - show real data
    auto info_section = vbox({
        text("Process Information:"),
        hbox({
            text(" Name: "),
            text(selected_process_info.name),
        }),
        hbox({
            text(" PID: "),
            text(std::to_string(selected_process_info.pid)),
        }),
        hbox({
            text(" Status: "),
            text(selected_process.has_value() ? "Selected" : "No Process"),
        }),
        separator(),
        text("Module Information:"),
        hbox({
            text(" Name: "),
            text(selected_module.name),
        }),
        hbox({
            text(" Base Address: "),
            text(selected_module.base_address),
        }),
        hbox({
            text(" Size: "),
            text(std::to_string(selected_module.size_kb) + " KB"),
        }),
    }) | border;

    // Selection info panels
    Element memory_info;
    if (memory_selected >= 0 && memory_selected < static_cast<int>(memory_entries.size()) &&
        selected_process.has_value() && !libmem_modules.empty()) {
        // Calculate the actual address for the selected row
        libmem::Address display_addr = 0;
        if (current_memory_address != 0) {
            display_addr = current_memory_address + (memory_scroll_offset * 16);
        } else if (module_selected >= 0 && module_selected < static_cast<int>(libmem_modules.size())) {
            display_addr = libmem_modules[module_selected].base + (memory_scroll_offset * 16);
        } else {
            display_addr = libmem_modules[0].base + (memory_scroll_offset * 16);
        }

        libmem::Address addr = display_addr + (memory_selected * 16);

        // Try to read real memory value at the selected address
        std::string addr_str = "N/A";
        std::string int_value_str = "N/A";
        std::string float_value_str = "N/A";
        std::string double_value_str = "N/A";

        try {
            std::vector<uint8_t> buffer(16, 0);
            size_t bytes_read = libmem::ReadMemory(&selected_process.value(), addr, buffer.data(), 16);

            // Format address
            std::stringstream ss;
            ss << "0x" << std::hex << std::setfill('0') << std::setw(12) << addr;
            addr_str = ss.str();

            if (bytes_read >= 4) {
                int32_t int_value = *reinterpret_cast<int32_t*>(buffer.data());
                uint32_t uint_value = *reinterpret_cast<uint32_t*>(buffer.data());

                // Format as both signed and unsigned
                std::stringstream is;
                is << std::dec << int_value << " (0x" << std::hex << std::setfill('0') << std::setw(8) << uint_value << ")";
                int_value_str = is.str();

                float float_value = *reinterpret_cast<float*>(buffer.data());
                std::stringstream fs;
                fs << std::dec << std::fixed << std::setprecision(6) << float_value;
                float_value_str = fs.str();
            }

            if (bytes_read >= 8) {
                double double_value = *reinterpret_cast<double*>(buffer.data());
                std::stringstream ds;
                ds << std::dec << std::fixed << std::setprecision(6) << double_value;
                double_value_str = ds.str();
            }
        } catch (...) {
            // Ignore errors
        }

        Elements memory_info_elements = {
            text("Selected Memory:") | bold,
            text("Address: " + addr_str),
            separator(),
            text("int32: " + int_value_str),
            text(""),
            text("float: " + float_value_str),
            text(""),
            text("double: " + double_value_str),
        };
        memory_info = vbox(memory_info_elements) | border;
    } else {
        // Show placeholder with instructions
        Elements placeholder_elements = {
            text("Selected Memory:") | bold,
            text(""),
            text("Navigate memory with"),
            text("arrow keys to view"),
            text("value interpretations"),
            text(""),
            text("↑↓ : Scroll"),
            text("PgUp/Dn : Fast scroll"),
        };
        memory_info = vbox(placeholder_elements) | border;
    }
    
    Element disasm_info;
    if (disasm_selected >= 0 && disasm_selected < static_cast<int>(disasm_entries.size()) &&
        selected_process.has_value() && !libmem_modules.empty()) {
        // Calculate the disassembly base address (same as used for generating disasm_entries)
        libmem::Address disasm_base = 0;

        // Calculate the address of the selected memory row
        if (memory_selected >= 0 && memory_selected < (int)memory_entries.size()) {
            // Use the same address calculation as the memory viewer
            libmem::Address display_addr = 0;
            if (current_memory_address != 0) {
                display_addr = current_memory_address + (memory_scroll_offset * 16);
            } else if (module_selected >= 0 && module_selected < (int)libmem_modules.size()) {
                display_addr = libmem_modules[module_selected].base + (memory_scroll_offset * 16);
            } else {
                display_addr = libmem_modules[0].base + (memory_scroll_offset * 16);
            }

            // Use the selected row's address
            disasm_base = display_addr + (memory_selected * 16);
        } else {
            // Fallback to module base if no memory selected
            disasm_base = libmem_modules[0].base;
        }

        // The selected instruction address is relative to disasm_base
        // We need to read from the actual disasm list to get the real address
        // For now, just show the disasm_base address as the selected instruction
        libmem::Address addr = disasm_base;
        std::string instruction_text = "No instruction data";

        try {
            // Read memory to get actual instruction bytes
            std::vector<uint8_t> inst_buffer(16, 0);
            size_t bytes_read = libmem::ReadMemory(&selected_process.value(), addr, inst_buffer.data(), inst_buffer.size());

            if (bytes_read > 0) {
                // Format the instruction bytes
                std::stringstream ss;
                ss << "[ ";
                for (size_t i = 0; i < std::min<size_t>(8, bytes_read); i++) {
                    ss << std::setfill('0') << std::setw(2) << std::hex << (int)inst_buffer[i] << " ";
                }
                ss << "]";
                instruction_text = ss.str();
            }
        } catch (const std::exception& e) {
            instruction_text = "Error reading instruction";
        }
        
        // Format address as hex
        std::stringstream addr_ss;
        addr_ss << "0x" << std::hex << std::setfill('0') << std::setw(12) << addr;

        Elements disasm_info_elements = {
            text("Selected Instruction:") | bold,
            text("Address: " + addr_ss.str()),
            text("Bytes: " + instruction_text),
            separator(),
            text("Index: " + std::to_string(disasm_selected)),
        };
        disasm_info = vbox(disasm_info_elements) | border;
    } else {
        // Show placeholder with instructions
        Elements placeholder_elements = {
            text("Selected Instruction:") | bold,
            text(""),
            text("Disassembly follows"),
            text("your memory selection"),
            text(""),
            text("Press D or ENTER in"),
            text("DISASSEMBLY panel for"),
            text("detailed view"),
        };
        disasm_info = vbox(placeholder_elements) | border;
    }

    // Create memory section
    auto memory_section = vbox({
        text(memory_title) | bold | color(active_panel == ActivePanel::MEMORY ? Color::YellowLight : Color::White),
        separator(),
        memory_menu->Render() | vscroll_indicator | frame | flex,
    });

    // Create disassembly section
    auto disasm_section = vbox({
        text(disasm_title) | bold | color(active_panel == ActivePanel::DISASSEMBLY ? Color::MagentaLight : Color::White),
        separator(),
        disasm_menu->Render() | vscroll_indicator | frame | flex,
    });

    // Build status bar with context-sensitive keybinds
    std::string keybinds = "";
    switch (active_panel) {
      case ActivePanel::PROCESSES:
        keybinds = "TAB:Next | F:Filter | ENTER:Select | Q:Quit";
        break;
      case ActivePanel::MODULES:
        keybinds = "TAB:Next | F:Filter | ENTER:View | Q:Quit";
        break;
      case ActivePanel::MEMORY:
        keybinds = "TAB:Next | ↑↓:Scroll | PgUp/Dn:Fast | Home/End:Jump | ENTER:Watch | S:Scan | G:Goto | Q:Quit";
        break;
      case ActivePanel::DISASSEMBLY:
        keybinds = "TAB:Next | ENTER:View | D:Disasm | Q:Quit";
        break;
    }

    auto status_bar = hbox({
      text(" Status: ") | bold,
      text(status_message),
      separator(),
      text(" | ") | bold,
      text(keybinds) | color(Color::Cyan),
    });

    return vbox({
              // Top panel with process and module lists - smaller
              hbox({
                process_section | flex,
                separator(),
                module_section | flex,
              }) | size(HEIGHT, LESS_THAN, 15),

              separator(),

              // Middle panel with disassembly and process info - smaller
              hbox({
                // Left side with disassembly
                disasm_section | flex,
                separator(),
                // Right side with process info
                info_section | size(WIDTH, LESS_THAN, 25),
              }) | size(HEIGHT, LESS_THAN, 15),

              separator(),

              // Bottom panel with memory display and instruction info - MUCH BIGGER
              hbox({
                // Left side with memory display - takes most space
                memory_section | flex,
                separator(),
                // Right side with instruction and memory info
                vbox({
                  disasm_info | size(HEIGHT, EQUAL, 12),
                  memory_info | size(HEIGHT, EQUAL, 12),
                }) | size(WIDTH, LESS_THAN, 35),
              }) | flex,

              separator(),

              // Status bar - compact
              status_bar,
          }) | border;
  });

  // Add event handling - COMPLETELY REWRITTEN
  auto with_key_events = CatchEvent(component, [&](Event event) {
    // Global keybinds

    // TAB - Switch between panels
    if (event == Event::Tab || event == Event::TabReverse) {
      int next_panel = (int)active_panel;
      if (event == Event::Tab) {
        next_panel = (next_panel + 1) % 4;
      } else {
        next_panel = (next_panel - 1 + 4) % 4;
      }
      active_panel = (ActivePanel)next_panel;
      status_message = "Switched to panel " + std::to_string(next_panel);
      return true;
    }

    // Q - Quit
    if (event == Event::Character('q') || event == Event::Character('Q')) {
      screen.Exit();
      return true;
    }

    // ESC - Exit filter/dialog modes
    if (event == Event::Escape) {
      if (show_process_filter) {
        show_process_filter = false;
        process_container->SetActiveChild(process_menu);
        status_message = "Filter closed";
        return true;
      }
      if (show_module_filter) {
        show_module_filter = false;
        module_container->SetActiveChild(module_menu);
        status_message = "Filter closed";
        return true;
      }
      if (show_signature_dialog) {
        show_signature_dialog = false;
        status_message = "Signature scan canceled";
        return true;
      }
      if (show_address_dialog) {
        show_address_dialog = false;
        status_message = "Goto canceled";
        return true;
      }
      return false;
    }

    // Panel-specific keybinds
    switch (active_panel) {
      case ActivePanel::PROCESSES: {
        // F - Toggle filter
        if (event == Event::Character('f') || event == Event::Character('F')) {
          show_process_filter = !show_process_filter;
          if (show_process_filter) {
            process_container->SetActiveChild(process_filter_input);
            status_message = "Filter mode active";
          } else {
            process_container->SetActiveChild(process_menu);
            status_message = "Filter mode closed";
          }
          return true;
        }

        // ENTER - Select process
        if (event == Event::Return && !show_process_filter) {
          if (process_selected >= 0 && process_selected < (int)filtered_processes.size()) {
            auto& selected_proc_info = filtered_processes[process_selected];

            // Find the corresponding libmem process
            for (const auto& proc : libmem_processes) {
              if (proc.pid == selected_proc_info.pid) {
                selected_process = proc;
                break;
              }
            }

            if (selected_process.has_value()) {
              // Load modules for the selected process
              auto modules_opt = libmem::EnumModules(&selected_process.value());
              if (modules_opt.has_value()) {
                libmem_modules = modules_opt.value();
                all_modules.clear();

                // Convert libmem::Module to ModuleInfo for display
                for (const auto& mod : libmem_modules) {
                  ModuleInfo info;
                  info.name = mod.name;
                  std::stringstream ss;
                  ss << "0x" << std::hex << mod.base;
                  info.base_address = ss.str();
                  info.size_kb = mod.size / 1024;
                  all_modules.push_back(info);
                }

                // Update filtered modules
                filtered_modules = all_modules;
                module_entries.clear();
                for (const auto& module : filtered_modules) {
                  module_entries.push_back(module.name);
                }

                module_selected = 0;
                active_panel = ActivePanel::MODULES;
                status_message = "Process selected: " + selected_proc_info.name + " (PID: " + std::to_string(selected_proc_info.pid) + ")";
              } else {
                status_message = "Failed to load modules for process";
              }
            } else {
              status_message = "Failed to select process";
            }
          }
          return true;
        }
        break;
      }

      case ActivePanel::MODULES: {
        // F - Toggle filter
        if (event == Event::Character('f') || event == Event::Character('F')) {
          show_module_filter = !show_module_filter;
          if (show_module_filter) {
            module_container->SetActiveChild(module_filter_input);
            status_message = "Filter mode active";
          } else {
            module_container->SetActiveChild(module_menu);
            status_message = "Filter mode closed";
          }
          return true;
        }

        // ENTER - View module memory
        if (event == Event::Return && !show_module_filter) {
          if (module_selected >= 0 && module_selected < (int)libmem_modules.size() &&
              selected_process.has_value()) {
            auto& mod = libmem_modules[module_selected];
            current_memory_address = mod.base;
            memory_scroll_offset = 0;
            active_panel = ActivePanel::MEMORY;
            status_message = "Viewing module: " + mod.name;
          }
          return true;
        }
        break;
      }

      case ActivePanel::MEMORY: {
        // S - Signature scan
        if (event == Event::Character('s') || event == Event::Character('S')) {
          if (selected_process.has_value()) {
            show_signature_dialog = true;
            status_message = "Enter signature pattern...";
          } else {
            status_message = "No process selected";
          }
          return true;
        }

        // G - Goto address
        if (event == Event::Character('g') || event == Event::Character('G')) {
          show_address_dialog = true;
          status_message = "Enter address...";
          return true;
        }

        // Arrow Up/Down - Scroll memory (1 row at a time for precision)
        if (event == Event::ArrowUp) {
          memory_scroll_offset = std::max(0, memory_scroll_offset - 1);
          std::stringstream ss;
          ss << "Scroll offset: " << memory_scroll_offset;
          status_message = ss.str();
          return true;
        }
        if (event == Event::ArrowDown) {
          memory_scroll_offset += 1;
          std::stringstream ss;
          ss << "Scroll offset: " << memory_scroll_offset;
          status_message = ss.str();
          return true;
        }

        // Page Up/Down - Scroll memory (faster, 20 rows)
        if (event == Event::PageUp) {
          memory_scroll_offset = std::max(0, memory_scroll_offset - 20);
          std::stringstream ss;
          ss << "Scrolled up - offset: " << memory_scroll_offset;
          status_message = ss.str();
          return true;
        }
        if (event == Event::PageDown) {
          memory_scroll_offset += 20;
          std::stringstream ss;
          ss << "Scrolled down - offset: " << memory_scroll_offset;
          status_message = ss.str();
          return true;
        }

        // Home/End - Jump to start/far in memory
        if (event == Event::Home) {
          memory_scroll_offset = 0;
          status_message = "Jumped to start of memory region";
          return true;
        }
        if (event == Event::End) {
          memory_scroll_offset += 100;
          status_message = "Jumped forward in memory";
          return true;
        }

        // ENTER - Watch memory region
        if (event == Event::Return) {
          if (memory_selected >= 0 && memory_selected < (int)memory_entries.size() &&
              selected_process.has_value() && !libmem_modules.empty()) {
            // Calculate address
            libmem::Address display_addr = 0;
            if (current_memory_address != 0) {
              display_addr = current_memory_address + (memory_scroll_offset * 16);
            } else if (module_selected >= 0 && module_selected < (int)libmem_modules.size()) {
              display_addr = libmem_modules[module_selected].base + (memory_scroll_offset * 16);
            } else {
              display_addr = libmem_modules[0].base + (memory_scroll_offset * 16);
            }

            libmem::Address addr = display_addr + (memory_selected * 16);
            watch_memory_region(selected_process.value(), addr, 64);
          }
          return true;
        }
        break;
      }

      case ActivePanel::DISASSEMBLY: {
        // D - Disassemble at address
        if (event == Event::Character('d') || event == Event::Character('D')) {
          if (disasm_selected >= 0 && disasm_selected < (int)disasm_entries.size() &&
              selected_process.has_value() && !libmem_modules.empty()) {
            libmem::Address base_addr = module_selected >= 0 && module_selected < (int)libmem_modules.size() ?
                                        libmem_modules[module_selected].base : libmem_modules[0].base;
            libmem::Address addr = base_addr + (disasm_selected * 4);
            disassemble_memory_region(selected_process.value(), addr, 20);
          }
          return true;
        }

        // ENTER - View disassembly
        if (event == Event::Return) {
          if (disasm_selected >= 0 && disasm_selected < (int)disasm_entries.size() &&
              selected_process.has_value() && !libmem_modules.empty()) {
            libmem::Address base_addr = module_selected >= 0 && module_selected < (int)libmem_modules.size() ?
                                        libmem_modules[module_selected].base : libmem_modules[0].base;
            libmem::Address addr = base_addr + (disasm_selected * 4);
            disassemble_memory_region(selected_process.value(), addr, 20);
          }
          return true;
        }
        break;
      }
    }

    return false;
  });

  // Start the main loop - no constant refresh needed
  screen.Loop(with_key_events);
}