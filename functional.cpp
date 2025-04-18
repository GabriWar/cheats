#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <chrono>                     // for milliseconds
#include <thread>                     // for sleep_for
#include <atomic>                     // for atomic
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/loop.hpp>  // Add this include for Loop class
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/screen/color.hpp>
#ifdef _WIN32
    #include "LIBMEMWIN/includeWIN/libmem/libmem.hpp"
#else
    #include "LIBMEMLIN/includeLIN/libmem/libmem.hpp"
#endif

using namespace ftxui;

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

// Forward declarations of functions used in handle_module_menu
void dump_module(const libmem::Process& process, const libmem::Module& module);
void find_bytes(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt);

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
 * Disassemble memory around a specific address using TUI
 * 
 * @param process The process to disassemble from
 * @param address The address to disassemble around
 * @param instruction_count How many instructions to show
 * @return true if disassembly was completed successfully
 */
bool disassemble_memory_region(const libmem::Process& process, libmem::Address address, int instruction_count = 10) {
    auto screen = ScreenInteractive::Fullscreen();
    
    // Data for the UI
    std::vector<std::string> disasm_lines;
    std::string status_message = "Disassembling memory at address: 0x" + std::to_string(address);
    bool disasm_success = false;
    
    // Buffer for reading memory to verify it's accessible
    std::vector<uint8_t> mem_buffer(128, 0); // Larger buffer to capture more instructions
    size_t bytes_read = libmem::ReadMemory(&process, address, mem_buffer.data(), mem_buffer.size());
    
    if (bytes_read < 16) { // Need at least a few bytes for meaningful disassembly
        disasm_lines.push_back("Error: Memory at address 0x" + std::to_string(address) + " is not accessible.");
        status_message = "Failed to access memory at target address";
    } else {
        // Show memory preview
        std::stringstream ss;
        ss << "Memory preview at target address: ";
        for (size_t i = 0; i < std::min<size_t>(16, bytes_read); i++) {
            char hex_buff[4];
            snprintf(hex_buff, sizeof(hex_buff), "%02X ", mem_buffer[i]);
            ss << hex_buff;
            if ((i + 1) % 8 == 0) ss << " ";
        }
        disasm_lines.push_back(ss.str());
        disasm_lines.push_back("");
        
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
                disasm_lines.push_back("Reached end of readable memory.");
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
                disasm_lines.push_back("Failed to disassemble at 0x" + std::to_string(current_addr));
                
                // Move forward by one byte and try again
                current_addr += 1;
                continue;
            }
            
            // Get the instruction
            const auto& inst = disasm_result->front();
            
            // Format instruction for display
            std::stringstream inst_ss;
            inst_ss << "0x" << std::hex << current_addr << std::dec << ": " 
                    << inst.mnemonic << " " << inst.op_str;
            
            // Add the bytes in hex format
            inst_ss << " -> [ ";
            for (size_t i = 0; i < inst.bytes.size(); i++) {
                char hex_buff[4];
                snprintf(hex_buff, sizeof(hex_buff), "%02X ", inst.bytes[i]);
                inst_ss << hex_buff;
            }
            inst_ss << "]";
            
            disasm_lines.push_back(inst_ss.str());
            
            // Check if this is a return instruction
            if (inst.mnemonic.find("ret") != std::string::npos) {
                disasm_lines.push_back("Found return instruction, stopping disassembly.");
                break;
            }
            
            // Move to next instruction
            current_addr += inst.bytes.size();
            instructions_found++;
        }
        
        if (instructions_found == 0) {
            disasm_lines.push_back("Failed to disassemble any instructions.");
            status_message = "Disassembly failed";
        } else {
            disasm_success = true;
            status_message = "Disassembly completed successfully";
        }
    }
    
    // Create components for the UI
    int selected_line = 0;
    auto disasm_menu = Menu(&disasm_lines, &selected_line);
    
    // Create container with the menu
    auto container = Container::Vertical({
        disasm_menu
    });
    
    // Add key event handling for quitting
    container |= CatchEvent([&](Event event) {
        // Quit on Escape, Q key, or Enter
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Escape || event == Event::Return) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        return false;  // Pass other events through
    });
    
    auto renderer_component = Renderer(container, [&]() -> Element {
        // Create elements for the UI
        Elements title_elements = {
            text("Memory Disassembly") | bold | color(Color::Blue) | center
        };
        
        Elements status_elements = {
            text(status_message) | color(disasm_success ? Color::Green : Color::Red) | center
        };
        
        Elements instructions_elements = {
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" ↑/↓ : Scroll disassembly"),
            text(" Enter/Esc/Q : Return to previous screen")
        };
        
        // Main document structure
        return vbox({
            vbox(title_elements),
            separator(),
            vbox(status_elements),
            separator(),
            hbox({
                disasm_menu->Render() | flex,
                vbox(instructions_elements) | size(WIDTH, EQUAL, 30)
            }),
            separator(),
            text(" Press any key to return") | center
        }) | border;
    });
    
    // Run the UI loop
    screen.Loop(renderer_component);
    
    return disasm_success;
}

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
    auto screen = ScreenInteractive::Fullscreen();
    
    // Data for the UI
    std::vector<uint8_t> memory_buffer(size, 0);
    std::vector<uint8_t> frozen_buffer(size, 0);
    std::string status_message = "Watching memory at address: 0x" + std::to_string(address);
    bool read_success = false;
    bool freeze_value = false;
    bool is_paused = false;
    std::string hex_representation;
    std::string int32_value = "N/A";
    std::string uint32_value = "N/A";
    std::string float_value = "N/A";
    std::string double_value = "N/A";
    std::string string_value;
    
    // For changing values
    std::string change_value_input;
    int change_type_selected = 0;
    std::vector<std::string> change_type_entries = {
        " Int32",
        " UInt32",
        " Float",
        " Double",
        " Hex",
        " String"
    };
    bool is_changing_value = false;
    
    // Function to read and update memory values
    auto update_memory_display = [&]() {
        if (is_paused) {
            return;
        }
        
        // If frozen, continuously write the frozen value to memory
        if (freeze_value && !frozen_buffer.empty()) {
            // Write the frozen value back to memory to maintain the freeze
            libmem::WriteMemory(&process, address, frozen_buffer.data(), size);
            
            // Verify the frozen value was written by reading back
            std::vector<uint8_t> verify_buffer(size, 0);
            size_t bytes_read = libmem::ReadMemory(&process, address, verify_buffer.data(), size);
            read_success = (bytes_read == size);
            
            // Use frozen buffer for display to keep UI consistent
            std::vector<uint8_t> display_buffer = frozen_buffer;
            
            // Format the memory for display
            // Hex representation
            hex_representation.clear();
            for (size_t i = 0; i < size; i++) {
                char hex_buff[4];
                snprintf(hex_buff, sizeof(hex_buff), "%02X ", display_buffer[i]);
                hex_representation += hex_buff;
                if ((i + 1) % 8 == 0) hex_representation += " ";
            }
            
            // Integer representation (32-bit)
            if (size >= 4) {
                int32_t int_val = *reinterpret_cast<int32_t*>(display_buffer.data());
                int32_value = std::to_string(int_val);
                uint32_t uint_val = *reinterpret_cast<uint32_t*>(display_buffer.data());
                uint32_value = std::to_string(uint_val);
            }
            
            // Float representation
            if (size >= 4) {
                float float_val = *reinterpret_cast<float*>(display_buffer.data());
                float_value = std::to_string(float_val);
            }
            
            // Double representation
            if (size >= 8) {
                double double_val = *reinterpret_cast<double*>(display_buffer.data());
                double_value = std::to_string(double_val);
            }
            
            // String representation
            string_value.clear();
            for (size_t i = 0; i < size; i++) {
                char c = display_buffer[i];
                if (c >= 32 && c <= 126) { // Printable ASCII
                    string_value += c;
                } else {
                    string_value += '.';
                }
            }
        } else {
            // Read from process memory
            size_t bytes_read = libmem::ReadMemory(&process, address, memory_buffer.data(), size);
            read_success = (bytes_read == size);
            
            if (read_success) {
                // Format the memory for display
                // Hex representation
                hex_representation.clear();
                for (size_t i = 0; i < size; i++) {
                    char hex_buff[4];
                    snprintf(hex_buff, sizeof(hex_buff), "%02X ", memory_buffer[i]);
                    hex_representation += hex_buff;
                    if ((i + 1) % 8 == 0) hex_representation += " ";
                }
                
                // Integer representation (32-bit)
                if (size >= 4) {
                    int32_t int_val = *reinterpret_cast<int32_t*>(memory_buffer.data());
                    int32_value = std::to_string(int_val);
                    uint32_t uint_val = *reinterpret_cast<uint32_t*>(memory_buffer.data());
                    uint32_value = std::to_string(uint_val);
                }
                
                // Float representation
                if (size >= 4) {
                    float float_val = *reinterpret_cast<float*>(memory_buffer.data());
                    float_value = std::to_string(float_val);
                }
                
                // Double representation
                if (size >= 8) {
                    double double_val = *reinterpret_cast<double*>(memory_buffer.data());
                    double_value = std::to_string(double_val);
                }
                
                // String representation
                string_value.clear();
                for (size_t i = 0; i < size; i++) {
                    char c = memory_buffer[i];
                    if (c >= 32 && c <= 126) { // Printable ASCII
                        string_value += c;
                    } else {
                        string_value += '.';
                    }
                }
            }
        }
    };
    
    // Function to toggle freeze state
    auto toggle_freeze = [&]() {
        if (!freeze_value) {
            // Take a snapshot of current memory to freeze
            frozen_buffer = memory_buffer;
            freeze_value = true;
            status_message = "Value frozen";
        } else {
            freeze_value = false;
            status_message = "Value unfrozen";
        }
    };
    
    // Function to toggle pause state
    auto toggle_pause = [&]() {
        is_paused = !is_paused;
        status_message = is_paused ? "Memory watching paused" : "Memory watching resumed";
    };
    
    // Function to set a new value to memory
    auto apply_value_change = [&](const std::string& input_value, int type_index) -> bool {
        std::vector<uint8_t> new_value(size, 0);
        bool success = false;
        
        try {
            if (type_index == 0 && size >= 4) { // Int32
                int32_t val = std::stoi(input_value);
                *reinterpret_cast<int32_t*>(new_value.data()) = val;
                success = true;
            } else if (type_index == 1 && size >= 4) { // UInt32
                uint32_t val = static_cast<uint32_t>(std::stoul(input_value));
                *reinterpret_cast<uint32_t*>(new_value.data()) = val;
                success = true;
            } else if (type_index == 2 && size >= 4) { // Float
                float val = std::stof(input_value);
                *reinterpret_cast<float*>(new_value.data()) = val;
                success = true;
            } else if (type_index == 3 && size >= 8) { // Double
                double val = std::stod(input_value);
                *reinterpret_cast<double*>(new_value.data()) = val;
                success = true;
            } else if (type_index == 4) { // Hex
                std::istringstream iss(input_value);
                std::string byte_str;
                size_t byte_idx = 0;
                
                while (iss >> byte_str && byte_idx < size) {
                    try {
                        uint8_t byte_val = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                        new_value[byte_idx++] = byte_val;
                    } catch (...) {
                        status_message = "Invalid hex value: " + byte_str;
                        return false;
                    }
                }
                success = true;
            } else if (type_index == 5) { // String
                size_t copy_size = std::min(input_value.size(), size);
                std::copy(input_value.begin(), input_value.begin() + copy_size, new_value.begin());
                success = true;
            }
        } catch (const std::exception& e) {
            status_message = "Error parsing value: " + std::string(e.what());
            return false;
        }
        
        if (!success) {
            status_message = "Failed to parse value";
            return false;
        }
        
        // Apply the change
        if (freeze_value) {
            // Just update the frozen buffer
            frozen_buffer = new_value;
            status_message = "Frozen value updated";
            return true;
        } else {
            // Write directly to memory
            size_t bytes_written = libmem::WriteMemory(&process, address, new_value.data(), size);
            if (bytes_written == size) {
                status_message = "Value changed successfully";
                return true;
            } else {
                status_message = "Failed to write memory";
                return false;
            }
        }
    };
    
    // Create input for changing values
    InputOption input_option;
    input_option.on_enter = [&] {
        // Always consume the Enter key to prevent newlines in the input field
        if (is_changing_value && !change_value_input.empty()) {
            if (apply_value_change(change_value_input, change_type_selected)) {
                // Successfully changed value
                is_changing_value = false;
                change_value_input = ""; // Clear input after successful change
            }
        }
        return true; // Always consume Enter key to prevent newlines
    };
    input_option.multiline = false; // Ensure input is single-line only
    
    auto input_component = Input(&change_value_input, "Enter new value", input_option);
    
    // Create type selection menu
    auto type_menu = Menu(&change_type_entries, &change_type_selected);
    
    // Create container for change value UI
    auto change_container = Container::Vertical({
        type_menu,
        input_component
    });
    
    // Initial memory read
    update_memory_display();
    
    // Flag to control auto-refresh
    std::atomic<bool> should_quit(false);
    
    // Start a thread to update the memory display periodically
    std::thread refresh_thread([&]() {
        while (!should_quit) {
            if (!is_paused) {
                update_memory_display();
                screen.PostEvent(Event::Custom);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Event handler component
    auto event_handler = CatchEvent([&](Event event) {
        if (is_changing_value) {
            // In change value mode
            if (event == Event::Escape) {
                is_changing_value = false;
                change_value_input = ""; // Clear input on cancel
                return true;
            }
            
            if (event == Event::Return) {
                if (!change_value_input.empty()) {
                    if (apply_value_change(change_value_input, change_type_selected)) {
                        // Successfully changed value
                        is_changing_value = false;
                        change_value_input = ""; // Clear input after successful change
                    }
                }
                return true; // Always consume Enter key to prevent newlines
            }
            
            // Let the input component handle other events
            return false;
        } else {
            // In regular mode
            // Freeze/Unfreeze on F key
            if (event.is_character() && (event.character() == "f" || event.character() == "F")) {
                toggle_freeze();
                return true;
            }
            
            // Change value on C key
            if (event.is_character() && (event.character() == "c" || event.character() == "C")) {
                is_changing_value = true;
                // Pre-fill the input field with the current value based on type
                switch (change_type_selected) {
                    case 0: change_value_input = int32_value; break;
                    case 1: change_value_input = uint32_value; break;
                    case 2: change_value_input = float_value; break;
                    case 3: change_value_input = double_value; break;
                    case 4: change_value_input = hex_representation; break;
                    case 5: change_value_input = string_value; break;
                }
                input_component->TakeFocus();
                return true;
            }
            
            // Pause/Resume on P key
            if (event.is_character() && (event.character() == "p" || event.character() == "P")) {
                toggle_pause();
                return true;
            }
            
            // Quit on Escape or Q key
            if (event == Event::Escape || 
                (event.is_character() && (event.character() == "q" || event.character() == "Q"))) {
                should_quit = true;
                screen.ExitLoopClosure()();
                return true;
            }
            
            return false;
        }
    });
    
    // Create the container with the event handler
    auto component = Container::Vertical({}) | event_handler;
    
    // Create the renderer function
    auto render_function = [&]() -> Element {
        // Determine status colors
        ftxui::Color status_color = read_success ? Color::Green : Color::Red;
        ftxui::Color freeze_color = freeze_value ? Color::Red : Color::Green;
        ftxui::Color pause_color = is_paused ? Color::Yellow : Color::Green;
        
        // Value display section
        Elements memory_values = {
            text(" Memory at address: 0x" + std::to_string(address)) | color(Color::Cyan) | bold,
            text(" "),
            hbox(text(" Status: "), 
                 text(freeze_value ? "FROZEN" : "Live") | color(freeze_color),
                 text(" | "),
                 text(is_paused ? "PAUSED" : "Watching") | color(pause_color)),
            text(" "),
            hbox(text(" Hex bytes:    "), text(hex_representation) | bold),
            hbox(text(" Int32:        "), text(int32_value) | bold),
            hbox(text(" UInt32:       "), text(uint32_value) | bold),
            hbox(text(" Float:        "), text(float_value) | bold),
            hbox(text(" Double:       "), text(double_value) | bold),
            hbox(text(" ASCII string: "), text(string_value) | bold),
        };
        
        // Status message
        Elements status_elements = {
            text(" Status: " + status_message) | color(status_color)
        };
        
        // Instructions
        Elements instruction_elements = {
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" F: Freeze/Unfreeze value"),
            text(" C: Change value"),
            text(" P: Pause/Resume watching"),
            text(" Esc/Q: Exit")
        };
        
        if (is_changing_value) {
            // Show value change UI
            return vbox({
                text("Memory Watch") | bold | color(Color::Blue) | center,
                separator(),
                vbox(memory_values),
                separator(),
                text(" Change Value") | bold | color(Color::Yellow),
                text(" "),
                text(" Select value type:"),
                type_menu->Render(),
                text(" "),
                text(" Enter new value:"),
                input_component->Render(),
                text(" "),
                text(" Press Enter to apply, Esc to cancel") | center,
                separator(),
                vbox(status_elements),
            }) | border;
        } else {
            // Show regular memory watch UI
            return vbox({
                text("Memory Watch") | bold | color(Color::Blue) | center,
                separator(),
                vbox(memory_values),
                separator(),
                vbox(status_elements),
                separator(),
                vbox(instruction_elements)
            }) | border;
        }
    };
    
    // Create renderer component that uses our render function
    auto renderer_component = Renderer(component, render_function);
    
    // Run the UI loop
    screen.Loop(renderer_component);
    
    // Cleanup
    should_quit = true;
    if (refresh_thread.joinable()) {
        refresh_thread.join();
    }
    
    return read_success;
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
 * Scan for an array of bytes in memory using a TUI interface
 * 
 * @param process The process to scan
 * @param module Optional module to limit the scan to
 */
void scan_for_bytes(const libmem::Process& process, const std::optional<libmem::Module>& module) {
    auto screen = ScreenInteractive::Fullscreen();
    
    // UI variables
    std::string signature_input;
    std::string status_message = "";
    bool has_result = false;
    libmem::Address result_address = 0;
    std::string result_info = "";
    
    // For action menu after scan
    int action_selected = 0;
    std::vector<std::string> action_entries = {
        " Disassemble at match location",
        " Watch memory at match location",
        " Back to module selection"
    };
    
    // Create input component for signature
    InputOption input_option;
    auto signature_component = Input(&signature_input, "Enter byte pattern (e.g., 48 8D 64 24 ? C6 05)", input_option);
    
    // Button to perform the scan
    auto scan_button = Button("Scan", [&] {
        if (signature_input.empty()) {
            status_message = "Please enter a byte pattern";
            return;
        }
        
        status_message = "Scanning for pattern: " + signature_input;
        
        // Perform the scan
        SignatureScanResult scan_result = scan_module_for_pattern(process, module, signature_input);
        
        if (scan_result.success) {
            has_result = true;
            result_address = scan_result.address;
            result_info = "Found pattern at address: 0x" + std::to_string(scan_result.address);
            status_message = "Scan completed successfully";
        } else {
            has_result = false;
            status_message = "Pattern not found";
        }
    });
    
    // Create action menu for when a match is found
    auto action_menu = Menu(&action_entries, &action_selected);
    
    // Create the dialog component structure
    auto action_container = Container::Vertical({
        action_menu
    });
    
    // Back button
    auto back_button = Button("Back", screen.ExitLoopClosure());
    
    // Create container with all components
    auto container = Container::Vertical({
        signature_component,
        scan_button,
        action_container,
        back_button
    });
    
    // Add keyboard event handling
    container |= CatchEvent([&](Event event) {
        if (event == Event::Escape || 
            (event.is_character() && (event.character() == "q" || event.character() == "Q"))) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        // If we have a result and Enter is pressed on action menu
        if (has_result && event == Event::Return && action_container->Focused()) {
            screen.ExitLoopClosure()();
            
            switch (action_selected) {
                case 0: // Disassemble
                    disassemble_memory_region(process, result_address);
                    break;
                case 1: { // Watch memory
                    // Watch memory at the found address (monitoring 16 bytes by default)
                    watch_memory_region(process, result_address, 16);
                    break;
                }
                case 2: // Back
                    // Just return to the previous screen
                    break;
            }
            
            return true;
        }
        
        return false;
    });
    
    // Module information for display
    std::string module_info = module.has_value() ? 
        module->name + " (Base: 0x" + std::to_string(module->base) + ")" : 
        "All Modules";
    
    auto renderer = Renderer(container, [&] {
        // Determine what to show - input form or result actions
        auto content = vbox({});
        
        if (has_result) {
            content = vbox({
                hbox(text(" Pattern: "), text(signature_input) | bold),
                hbox(text(" Result: "), text(result_info) | color(Color::Green) | bold),
                separator(),
                text(" Choose an action:") | color(Color::Yellow),
                action_menu->Render() | flex,
                separator(),
                hbox(text(" "), back_button->Render())
            });
        } else {
            content = vbox({
                text(" Enter byte pattern to search for:") | color(Color::Yellow),
                hbox(text(" "), signature_component->Render() | flex),
                separator(),
                hbox(text(" "), scan_button->Render()),
                status_message.empty() ? text("") : separator(),
                status_message.empty() ? text("") : 
                    text(" " + status_message) | color(status_message.find("not found") != std::string::npos ? Color::Red : Color::Green),
                separator(),
                text(" Instructions:") | bold | color(Color::Yellow),
                text(" "),
                text(" Enter a byte pattern using spaces between bytes"),
                text(" Use ? or ?? as wildcards for unknown bytes"),
                text(" Example: 48 8D 64 24 ? C6 05 ? ? ? ? ?"),
                separator(),
                hbox(text(" "), back_button->Render())
            });
        }
        
        // Main document structure
        return vbox({
            text("Scan for Byte Pattern - Process: " + process.name) | bold | color(Color::Blue) | center,
            text("Module: " + module_info) | color(Color::Cyan) | center,
            separator(),
            content
        }) | border;
    });
    
    screen.Loop(renderer);
}

/**
 * Displays a menu of actions that can be performed on a process/module
 * 
 * @param process The process to perform actions on
 * @param module Optional module if a specific module was selected
 * @return The selected action
 */
ProcessAction show_process_actions(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt) {
    // Create a fullscreen terminal
    auto screen = ScreenInteractive::Fullscreen();
    
    // Data for the UI
    int selected = 0;
    std::vector<std::string> menu_entries = {
        " Scan for array of bytes",
        " Enter memory address",
        " Back to module selection"
    };
    
    // Create the menu component
    auto menu = Menu(&menu_entries, &selected);
    
    // Create component container with the menu
    auto container = Container::Vertical({
        menu
    });
    
    // Add key event handling for quitting, selecting
    container |= CatchEvent([&](Event event) {
        // Back to module list on Escape or B key
        if (event.is_character() && (event.character() == "b" || event.character() == "B")) {
            selected = 2; // Back to module selection
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Quit completely on Q key
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            selected = -1; // Mark as canceled
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Escape) {
            selected = 2; // Back to module selection
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Select on Enter key
        if (event == Event::Return) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        return false;  // Pass other events through
    });
    
    // Module information text
    std::string module_info = module.has_value() ? 
        module->name + " (Base: 0x" + std::to_string(module->base) + ")" : 
        "All Modules";
    
    auto renderer = Renderer(container, [&] {
        // Create elements for the UI
        Elements title_elements = {
            text("Process Actions - " + process.name + " (PID: " + std::to_string(process.pid) + ")") | bold | color(Color::Blue) | center,
            text("Module: " + module_info) | color(Color::Cyan) | center
        };
        
        Elements instructions_elements = {
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" ↑/↓ : Navigate list"),
            text(" Enter : Select action"),
            text(" Esc/B : Back to module list"),
            text(" Q : Quit")
        };
        
        // Main document structure
        return vbox({
            vbox(title_elements),
            separator(),
            hbox({
                menu->Render() | flex,
                vbox(instructions_elements) | size(WIDTH, EQUAL, 30)
            }),
        }) | border;
    });
    
    screen.Loop(renderer);
    
    if (selected < 0) {
        std::cout << "Process action selection canceled." << std::endl;
        return ProcessAction::CANCEL;
    } else if (selected == 0) {
        return ProcessAction::SCAN_BYTES;
    } else if (selected == 1) {
        return ProcessAction::ENTER_ADDRESS;
    } else {
        return ProcessAction::BACK_TO_MODULES;
    }
}

/**
 * Enter a specific memory address to examine
 * 
 * @param process The process to examine
 * @param module Optional module context
 */
void enter_memory_address(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt) {
    // Create a fullscreen terminal
    auto screen = ScreenInteractive::Fullscreen();
    
    // Input and state variables
    std::string address_input;
    std::string status_message = "";
    bool has_error = false;
    bool has_address = false;
    libmem::Address parsed_address = 0;
    
    // Action selection
    int action_selected = 0;
    std::vector<std::string> action_entries = {
        " Disassemble memory at address",
        " Watch memory at address",
        " Back to module selection"
    };
    
    // Create input component for address
    InputOption input_option;
    input_option.on_enter = [&] {
        try {
            // Try to parse the address - support both decimal and hex
            if (address_input.substr(0, 2) == "0x") {
                parsed_address = std::stoull(address_input.substr(2), nullptr, 16);
            } else {
                parsed_address = std::stoull(address_input, nullptr, 0);
            }
            
            // Validate the address (basic check)
            if (parsed_address == 0) {
                status_message = "Invalid address: cannot be zero";
                has_error = true;
                has_address = false;
                return;
            }
            
            status_message = "Address parsed: 0x" + std::to_string(parsed_address);
            has_error = false;
            has_address = true;
        } catch (const std::exception& e) {
            status_message = "Invalid address format: " + std::string(e.what());
            has_error = true;
            has_address = false;
        }
    };
    auto address_input_component = Input(&address_input, "Enter memory address (e.g., 0x7FF45CB00000)", input_option);
    
    // Create action menu
    auto action_menu = Menu(&action_entries, &action_selected);
    
    // Create container with the input and menu
    auto container = Container::Vertical({
        address_input_component,
        action_menu
    });
    
    // Add key event handling
    container |= CatchEvent([&](Event event) {
        // Back to previous menu on Escape or B key
        if (event.is_character() && (event.character() == "b" || event.character() == "B")) {
            action_selected = 2; // Back to module selection
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Quit on Q key
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            action_selected = -1; // Cancel
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Escape) {
            action_selected = 2; // Back to module selection
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Select on Enter key if we have a valid address
        if (event == Event::Return && action_menu->Focused() && has_address) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        return false;  // Pass other events through
    });
    
    // Module information text
    std::string module_info = module.has_value() ? 
        module->name + " (Base: 0x" + std::to_string(module->base) + ")" : 
        "All Modules";
    
    auto renderer = ftxui::Renderer(container, [&] {
        // Title area
        auto title = vbox({
            text("Enter Memory Address - " + process.name + " (PID: " + std::to_string(process.pid) + ")") | bold | color(Color::Blue) | center,
            text("Module: " + module_info) | color(Color::Cyan) | center
        });
        
        // Input area
        auto input_area = vbox({
            text(" Enter a memory address to examine:") | color(Color::Yellow),
            hbox(text(" "), address_input_component->Render() | flex)
        });
        
        // Status message
        auto status_area = text("");
        if (!status_message.empty()) {
            status_area = vbox({
                separator(),
                text(" " + status_message) | (has_error ? color(Color::Red) : color(Color::Green))
            });
        }
        
        // Action menu
        auto action_area = text("");
        if (has_address) {
            action_area = vbox({
                text(" Choose action:") | color(Color::Yellow),
                action_menu->Render() | flex
            });
        }
        
        // Instructions
        auto instructions = vbox({
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" Enter: Parse address or select action"),
            text(" Tab: Switch between input and menu"),
            text(" Esc/B: Back to module list"),
            text(" Q: Quit")
        });
        
        // Main document structure
        return vbox({
            title,
            separator(),
            input_area,
            status_area,
            separator(),
            action_area,
            separator(),
            instructions | size(HEIGHT, EQUAL, 6)
        }) | border;
    });
    
    screen.Loop(renderer);
    
    // Perform the selected action
    if (has_address && action_selected >= 0 && action_selected < 2) {
        if (action_selected == 0) {
            // Disassemble memory
            disassemble_memory_region(process, parsed_address);
        } else if (action_selected == 1) {
            // Watch memory
            watch_memory_region(process, parsed_address);
        }
    }
}

/**
 * Displays a fullscreen list of processes using FTXUI and libmem, allowing the user to select one.
 * 
 * @return The PID of the selected process, or 0 if failed/canceled
 */
libmem::Pid process_select() {
    // Create a fullscreen terminal
    auto screen = ScreenInteractive::Fullscreen();
    
    // Get processes using libmem
    std::vector<libmem::Process> processes;
    auto processes_opt = libmem::EnumProcesses();
    
    if (!processes_opt.has_value()) {
        std::cout << "Failed to enumerate processes." << std::endl;
        return 0;
    }
    
    processes = processes_opt.value();
    std::cout << "Found " << processes.size() << " processes" << std::endl;
    
    // Data for the UI
    int selected = 0;
    std::vector<std::string> menu_entries;
    std::vector<libmem::Process> filtered_processes = processes;
    std::string filter_value;
    bool focus_filter = false;
    
    // Create initial menu entries for each process
    for (const auto& process : processes) {
        std::string entry_text = " PID: " + std::to_string(process.pid) + " | " + process.name;
        menu_entries.push_back(entry_text);
    }
    
    // Function to filter processes based on user input
    auto filter_processes = [&]() {
        filtered_processes.clear();
        menu_entries.clear();
        
        // If filter is empty, show all processes
        if (filter_value.empty()) {
            filtered_processes = processes;
            for (const auto& process : processes) {
                std::string entry_text = " PID: " + std::to_string(process.pid) + " | " + process.name;
                menu_entries.push_back(entry_text);
            }
            return;
        }
        
        // Convert filter to lowercase for case-insensitive comparison
        std::string filter_lower = filter_value;
        std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
                      [](unsigned char c){ return std::tolower(c); });
        
        // Filter processes by name or PID
        for (const auto& process : processes) {
            std::string name_lower = process.name;
            std::string pid_str = std::to_string(process.pid);
            
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                          [](unsigned char c){ return std::tolower(c); });
            
            if (name_lower.find(filter_lower) != std::string::npos || 
                pid_str.find(filter_value) != std::string::npos) {
                filtered_processes.push_back(process);
                std::string entry_text = " PID: " + std::to_string(process.pid) + " | " + process.name;
                menu_entries.push_back(entry_text);
            }
        }
        
        // Reset selection if it's now out of bounds
        if (selected >= (int)filtered_processes.size()) {
            selected = filtered_processes.size() > 0 ? 0 : -1;
        }
    };
    
    // Create the menu component
    auto menu = Menu(&menu_entries, &selected);
    
    // Filter input for searching processes
    InputOption filter_option;
    filter_option.on_change = [&] { 
        filter_processes(); 
    };
    auto filter_input = Input(&filter_value, "Filter by process name or PID", filter_option);
    
    // Create component container with the filter and menu
    auto container = Container::Vertical({
        filter_input,
        menu
    });
    
    // Add key event handling for quitting, selecting, and focusing filter
    container |= CatchEvent([&](Event event) {
        // Quit on Escape or Q key
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            selected = -1; // Mark as canceled
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Escape) {
            selected = -1; // Mark as canceled
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Select on Enter key
        if (event == Event::Return && selected >= 0 && selected < (int)filtered_processes.size()) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Press 'f' to focus on filter input
        if (event.is_character() && (event.character() == "f" || event.character() == "F")) {
            focus_filter = true;
            return true;
        }
        
        return false;  // Pass other events through
    });
    
    auto renderer = Renderer(container, [&] {
        // Process details section
        std::string pid_str = (selected >= 0 && selected < (int)filtered_processes.size()) 
                             ? std::to_string(filtered_processes[selected].pid) : "N/A";
        std::string name_str = (selected >= 0 && selected < (int)filtered_processes.size()) 
                             ? filtered_processes[selected].name : "N/A";
        std::string path_str = (selected >= 0 && selected < (int)filtered_processes.size()) 
                             ? filtered_processes[selected].path : "N/A";
        std::string bits_str = (selected >= 0 && selected < (int)filtered_processes.size()) 
                             ? std::to_string(filtered_processes[selected].bits) : "N/A";
        
        // Create elements for the UI
        Elements title_elements = {
            text("Process Selection") | bold | color(Color::Blue) | center
        };
        
        Elements filter_elements = {
            hbox(text(" Filter: "), filter_input->Render() | flex)
        };
        
        Elements details_elements = {
            text(" Process Details:") | bold | color(Color::Green),
            text(" "),
            hbox(text(" PID: "), text(pid_str) | bold),
            hbox(text(" Name: "), text(name_str)),
            hbox(text(" Path: "), text(path_str)),
            hbox(text(" Architecture: "), text(bits_str + "-bit"))
        };
        
        Elements instructions_elements = {
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" ↑/↓ : Navigate list"),
            text(" Enter : Select process"),
            text(" Esc/Q : Exit/Cancel"),
            text(" F : Focus on filter"),
            text(" Type : Filter processes")
        };
        
        // Show how many processes are being displayed
        std::string stats = " Showing " + std::to_string(filtered_processes.size()) + 
                           " of " + std::to_string(processes.size()) + " processes";
        
        // Set focus to filter input if the 'f' key was pressed
        if (focus_filter) {
            filter_input->TakeFocus();
            focus_filter = false;
        }
        
        // Main document structure
        return vbox({
            vbox(title_elements),
            separator(),
            vbox(filter_elements),
            separator(),
            hbox({
                vbox(details_elements) | size(WIDTH, EQUAL, 50),
                vbox(instructions_elements) | size(WIDTH, EQUAL, 30)
            }),
            separator(),
            menu->Render() | flex | frame,
            separator(),
            text(stats) | center
        }) | border;
    });
    
    screen.Loop(renderer);
    
    // Return the selected process PID or 0 if canceled
    if (selected < 0 || selected >= (int)filtered_processes.size()) {
        std::cout << "Process selection canceled." << std::endl;
        return 0;
    }
    
    std::cout << "Selected process: " << filtered_processes[selected].name 
              << " (PID: " << filtered_processes[selected].pid << ")" << std::endl;
    
    return filtered_processes[selected].pid;
}

/**
 * Displays a fullscreen list of modules in a process using FTXUI and libmem.
 * 
 * @param process The process to show modules for
 * @return ModuleSelectionResult containing selected module information
 */
ModuleSelectionResult module_select(const libmem::Process& process) {
    ModuleSelectionResult result;
    
    // Create a fullscreen terminal
    auto screen = ScreenInteractive::Fullscreen();
    
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
    
    // Data for the UI
    int selected = 0;
    std::vector<std::string> menu_entries;
    std::vector<libmem::Module> filtered_modules;
    std::string filter_value;
    bool focus_filter = false;
    
    // Function to create menu entries with the "Select All Modules" option first
    auto create_menu_entries = [&](const std::vector<libmem::Module>& mod_list) {
        menu_entries.clear();
        filtered_modules.clear();
        
        // Add "Select All Modules" as the first option
        menu_entries.push_back(" [Select All Modules]");
        
        // Add modules to the filtered list and menu entries
        for (const auto& module : mod_list) {
            filtered_modules.push_back(module);
            std::string entry_text = " " + module.name + " (Base: 0x" + 
                                  std::to_string(module.base) + ", Size: " + 
                                  std::to_string(module.size) + " bytes)";
            menu_entries.push_back(entry_text);
        }
    };
    
    // Initial population of the menu
    create_menu_entries(modules);
    
    // Function to filter modules based on user input
    auto filter_modules = [&]() {
        std::vector<libmem::Module> matching_modules;
        
        // If filter is empty, show all modules
        if (filter_value.empty()) {
            matching_modules = modules;
        } else {
            // Convert filter to lowercase for case-insensitive comparison
            std::string filter_lower = filter_value;
            std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
                          [](unsigned char c){ return std::tolower(c); });
            
            // Filter modules by name or address
            for (const auto& module : modules) {
                std::string name_lower = module.name;
                std::string path_lower = module.path;
                std::string addr_str = "0x" + std::to_string(module.base);
                
                std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(),
                              [](unsigned char c){ return std::tolower(c); });
                
                if (name_lower.find(filter_lower) != std::string::npos || 
                    path_lower.find(filter_lower) != std::string::npos ||
                    addr_str.find(filter_value) != std::string::npos) {
                    matching_modules.push_back(module);
                }
            }
        }
        
        create_menu_entries(matching_modules);
        
        // Reset selection if it's now out of bounds
        if (selected >= (int)menu_entries.size()) {
            selected = menu_entries.size() > 0 ? 0 : 0;
        }
    };
    
    // Create the menu component
    auto menu = Menu(&menu_entries, &selected);
    
    // Filter input for searching modules
    InputOption filter_option;
    filter_option.on_change = [&] { 
        filter_modules(); 
    };
    auto filter_input = Input(&filter_value, "Filter by module name or address", filter_option);
    
    // Create component container with the filter and menu
    auto container = Container::Vertical({
        filter_input,
        menu
    });
    
    // Add key event handling for quitting, selecting, and focusing filter
    container |= CatchEvent([&](Event event) {
        // Back to process list on Escape or B key
        if (event.is_character() && (event.character() == "b" || event.character() == "B")) {
            result.back_to_process_list = true;
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Quit completely on Q key
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            selected = -1; // Mark as canceled
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Escape) {
            result.back_to_process_list = true;
            screen.ExitLoopClosure()();
            return true;
        }
        
        // Select on Enter key
        if (event == Event::Return) {
            if (selected == 0) {
                // "Select All Modules" was chosen
                result.success = true;
                result.select_all_modules = true;
                screen.ExitLoopClosure()();
                return true;
            } else if (selected > 0 && selected <= (int)filtered_modules.size()) {
                // A specific module was selected
                result.success = true;
                result.selected_module = filtered_modules[selected - 1]; // -1 because of "Select All" option
                screen.ExitLoopClosure()();
                return true;
            }
        }
        
        // Press 'f' to focus on filter input
        if (event.is_character() && (event.character() == "f" || event.character() == "F")) {
            focus_filter = true;
            return true;
        }
        
        return false;  // Pass other events through
    });
    
    auto renderer = Renderer(container, [&] {
        // Module details section
        std::string base_str = "N/A";
        std::string end_str = "N/A";
        std::string size_str = "N/A";
        std::string name_str = "N/A";
        std::string path_str = "N/A";
        
        // Get details for the selected module
        if (selected > 0 && selected <= (int)filtered_modules.size()) {
            const auto& module = filtered_modules[selected - 1]; // -1 because of "Select All" option
            base_str = "0x" + std::to_string(module.base);
            end_str = "0x" + std::to_string(module.end);
            size_str = std::to_string(module.size) + " bytes";
            name_str = module.name;
            path_str = module.path;
        } else if (selected == 0) {
            // "Select All Modules" option
            name_str = "All Modules";
            size_str = std::to_string(modules.size()) + " modules total";
        }
        
        // Create elements for the UI
        Elements title_elements = {
            text("Module List - Process: " + process.name + " (PID: " + std::to_string(process.pid) + ")") | bold | color(Color::Blue) | center
        };
        
        Elements filter_elements = {
            hbox(text(" Filter: "), filter_input->Render() | flex)
        };
        
        Elements details_elements = {
            text(" Module Details:") | bold | color(Color::Green),
            text(" "),
            hbox(text(" Name: "), text(name_str) | bold),
            hbox(text(" Base Address: "), text(base_str)),
            hbox(text(" End Address: "), text(end_str)),
            hbox(text(" Size: "), text(size_str)),
            hbox(text(" Path: "), text(path_str))
        };
        
        Elements instructions_elements = {
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" ↑/↓ : Navigate list"),
            text(" Enter : Select module/option"),
            text(" Esc/B : Back to process list"),
            text(" Q : Quit"),
            text(" F : Focus on filter"),
            text(" Type : Filter modules")
        };
        
        // Show how many modules are being displayed
        std::string stats = " Showing " + std::to_string(filtered_modules.size()) + 
                           " of " + std::to_string(modules.size()) + " modules";
        
        // Set focus to filter input if the 'f' key was pressed
        if (focus_filter) {
            filter_input->TakeFocus();
            focus_filter = false;
        }
        
        // Main document structure
        return vbox({
            vbox(title_elements),
            separator(),
            vbox(filter_elements),
            separator(),
            hbox({
                vbox(details_elements) | size(WIDTH, EQUAL, 50),
                vbox(instructions_elements) | size(WIDTH, EQUAL, 30)
            }),
            separator(),
            menu->Render() | flex | frame,
            separator(),
            text(stats) | center
        }) | border;
    });
    
    screen.Loop(renderer);
    
    if (selected < 0) {
        std::cout << "Module selection canceled." << std::endl;
    } else if (selected == 0) {
        std::cout << "Selected all modules." << std::endl;
    } else if (selected <= (int)filtered_modules.size()) {
        std::cout << "Selected module: " << filtered_modules[selected - 1].name 
              << " (Base: 0x" << filtered_modules[selected - 1].base << ")" << std::endl;
    }
    
    return result;
}

/**
 * Displays a fullscreen list of modules in a process using FTXUI and libmem.
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
    return module_select(process);
}

void handle_module_menu(const libmem::Process& process, const std::vector<libmem::Module>& modules, int selected_module) {
    auto screen = ScreenInteractive::Fullscreen();
    
    std::string input;
    int entries_selected = 0;
    std::vector<std::string> entries = {
        " Dump module",
        " Find bytes in memory",
        " Disassemble memory region",
        " Watch memory region",
        " Enter memory address",
        " Back to process list"
    };
    
    auto container = Container::Vertical({
        Menu(&entries, &entries_selected)
    });
    
    container |= CatchEvent([&](Event event) {
        if (event == Event::Escape || (event.is_character() && (event.character() == "b" || event.character() == "B"))) {
            entries_selected = entries.size() - 1; // Back to process list
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            entries_selected = -1; // Exit program
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Return) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        return false;
    });
    
    std::string module_name;
    if (selected_module == -1) {
        module_name = "All Modules";
    } else {
        module_name = modules[selected_module].name;
    }
    
    auto renderer = Renderer(container, [&, module_name, process] {
        return vbox({
            text("Module Menu - " + process.name + " (PID: " + std::to_string(process.pid) + ")") | bold | color(Color::Blue) | center,
            text("Selected Module: " + module_name) | color(Color::Cyan) | center,
            separator(),
            container->Render(),
            separator(),
            text(" Esc/B: Back to process list") | color(Color::Yellow),
            text(" Q: Quit") | color(Color::Yellow)
        }) | border;
    });
    
    screen.Loop(renderer);
    
    // Handle menu selection
    if (entries_selected >= 0) {
        if (entries_selected == 0) {
            // Dump module
            if (selected_module != -1) {
                dump_module(process, modules[selected_module]);
            }
        } else if (entries_selected == 1) {
            // Find bytes
            if (selected_module != -1) {
                find_bytes(process, modules[selected_module]);
            } else {
                find_bytes(process, std::nullopt);
            }
        } else if (entries_selected == 2) {
            // Disassemble memory region
            if (selected_module != -1) {
                disassemble_memory_region(process, modules[selected_module].base);
            }
        } else if (entries_selected == 3) {
            // Watch memory region
            if (selected_module != -1) {
                watch_memory_region(process, modules[selected_module].base);
            }
        } else if (entries_selected == 4) {
            // Enter memory address
            if (selected_module != -1) {
                enter_memory_address(process, modules[selected_module]);
            } else {
                enter_memory_address(process);
            }
        } else if (entries_selected == 5) {
            // Back to process list - do nothing, loop will exit
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
    auto screen = ScreenInteractive::Fullscreen();
    
    // Data for the UI
    std::string status_message = "Dumping module: " + module.name;
    std::vector<std::string> dump_lines;
    
    // Add module information
    dump_lines.push_back("Module: " + module.name);
    dump_lines.push_back("Path: " + module.path);
    dump_lines.push_back("Base address: 0x" + std::to_string(module.base));
    dump_lines.push_back("End address: 0x" + std::to_string(module.end));
    dump_lines.push_back("Size: " + std::to_string(module.size) + " bytes");
    dump_lines.push_back("");
    
    // Add memory preview of the first 1024 bytes or less
    const size_t preview_size = std::min<size_t>(1024, module.size);
    std::vector<uint8_t> memory_buffer(preview_size, 0);
    size_t bytes_read = libmem::ReadMemory(&process, module.base, memory_buffer.data(), preview_size);
    
    if (bytes_read > 0) {
        dump_lines.push_back("Memory preview (first " + std::to_string(bytes_read) + " bytes):");
        
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
            
            dump_lines.push_back(line.str());
            
            // Limit the number of lines to display
            if (dump_lines.size() >= 500) {
                dump_lines.push_back("... (output truncated, module too large to display completely)");
                break;
            }
        }
    } else {
        dump_lines.push_back("Failed to read module memory.");
    }
    
    // Create components for the UI
    int selected_line = 0;
    auto dump_menu = Menu(&dump_lines, &selected_line);
    
    // Create container with the menu
    auto container = Container::Vertical({
        dump_menu
    });
    
    // Add key event handling for quitting
    container |= CatchEvent([&](Event event) {
        // Quit on Escape, Q key, or Enter
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Escape || event == Event::Return) {
            screen.ExitLoopClosure()();
            return true;
        }
        
        return false;  // Pass other events through
    });
    
    auto renderer = Renderer(container, [&] {
        // Create elements for the UI
        Elements title_elements = {
            text("Module Dump") | bold | color(Color::Blue) | center
        };
        
        Elements status_elements = {
            text(status_message) | color(Color::Green) | center
        };
        
        Elements instructions_elements = {
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" ↑/↓ : Scroll dump"),
            text(" Enter/Esc/Q : Return to previous screen")
        };
        
        // Main document structure
        return vbox({
            vbox(title_elements),
            separator(),
            vbox(status_elements),
            separator(),
            hbox({
                dump_menu->Render() | flex,
                vbox(instructions_elements) | size(WIDTH, EQUAL, 30)
            }),
            separator(),
            text(" Press any key to return") | center
        }) | border;
    });
    
    screen.Loop(renderer);
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

int main() {
    bool quit = false;
    
    while (!quit) {
        libmem::Pid selected_pid = process_select();
        
        if (selected_pid == 0) {
            std::cout << "No process selected or operation canceled." << std::endl;
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