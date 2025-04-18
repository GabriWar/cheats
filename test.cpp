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
        // Read memory from the process - use correct API
        std::vector<uint8_t> memory_buffer(instruction_count * 16); // Average instruction size is less than 16 bytes
        bool read_success = true;
        
        // Read memory one byte at a time using template version
        for (size_t i = 0; i < memory_buffer.size(); i++) {
            try {
                memory_buffer[i] = libmem::ReadMemory<uint8_t>(address + i);
            } catch (...) {
                // If we can't read, fill with zero
                memory_buffer[i] = 0;
                read_success = false;
            }
        }
        
        if (!read_success) {
            status_message = "Failed to read some memory at address " + FormatAsHex(address);
        }
        
        if (memory_buffer.empty()) {
            status_message = "Failed to read memory at address " + FormatAsHex(address);
            return false;
        }
        
        // Convert to disassembly lines
        size_t total_bytes_read = 0;
        libmem::Address current_address = address;
        
        // In real implementation, use a disassembler library
        // For now, just display hex bytes as placeholder
        for (int i = 0; i < instruction_count && total_bytes_read < memory_buffer.size(); i++) {
            size_t bytes_for_instr = std::min(size_t(16), memory_buffer.size() - total_bytes_read);
            std::string bytes_str;
            
            for (size_t j = 0; j < bytes_for_instr; j++) {
                if (j > 0) bytes_str += " ";
                bytes_str += std::to_string(memory_buffer[total_bytes_read + j]);
            }
            
            std::string line = FormatAsHex(current_address) + ": " + bytes_str;
            disasm_lines.push_back(line);
            
            current_address += bytes_for_instr;
            total_bytes_read += bytes_for_instr;
        }
        
        status_message = "Disassembly complete - " + std::to_string(disasm_lines.size()) + " instructions";
    } catch (const std::exception& e) {
        status_message = "Error: " + std::string(e.what());
        return false;
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
    std::vector<uint64_t> memory_values;
    std::string status_message = "Watching memory...";
    int selected_index = 0;
    bool is_running = true;
    bool paused = false;
    bool freeze_value = false;
    std::vector<uint64_t> frozen_buffer;
    
    // Maximum rows to display
    const int max_rows = 16;
    const int bytes_per_row = 16;
    size = std::min(size_t(max_rows * bytes_per_row), size);
    
    // Read initial memory values
    try {
        memory_values.resize(size / sizeof(uint64_t) + 1, 0);
        for (size_t i = 0; i < memory_values.size(); i++) {
            libmem::Address curr_addr = address + (i * sizeof(uint64_t));
            memory_values[i] = libmem::ReadMemory<uint64_t>(curr_addr);
        }
        
        if (memory_values.empty()) {
            status_message = "Failed to read memory at address " + FormatAsHex(address);
            return false;
        }
        
        // Generate initial display
        for (size_t i = 0; i < memory_values.size(); i++) {
            libmem::Address row_addr = address + (i * sizeof(uint64_t));
            std::string line = FormatAsHex(row_addr) + ": " + 
                              FormatHexBytes(memory_values[i], sizeof(uint64_t)) + "  " +
                              FormatAsAscii(memory_values[i], sizeof(uint64_t));
            memory_lines.push_back(line);
        }
    } catch (const std::exception& e) {
        status_message = "Error: " + std::string(e.what());
        return false;
    }
    
    // Prepare component for memory display
    auto menu_option = MenuOption();
    menu_option.on_change = [&] { 
        status_message = "Selected: " + memory_lines[selected_index];
    };
    
    auto memory_component = Menu(&memory_lines, &selected_index, menu_option);
    
    // Value type and edit features
    std::string edit_value;
    bool editing = false;
    int type_index = 0; // 0=int64, 1=float, 2=double, 3=bytes
    std::vector<std::string> type_names = {"int64_t", "float", "double", "bytes"};
    
    auto input_component = Input(&edit_value, "Enter new value");
    auto type_selector = Radiobox(&type_names, &type_index);
    
    // Function to apply value changes
    auto apply_value_change = [&](const std::string& input_value, int type_index) -> bool {
        if (input_value.empty()) {
            status_message = "No value entered";
            return false;
        }
        
        try {
            // Calculate address of selected item
            libmem::Address target_addr = address + (selected_index * sizeof(uint64_t));
            uint64_t value = 0;
            
            // Convert based on type
            switch (type_index) {
                case 0: { // int64
                    std::istringstream iss(input_value);
                    int64_t int_val;
                    
                    // Try to parse as hex if it starts with 0x
                    if (input_value.substr(0, 2) == "0x") {
                        iss >> std::hex >> int_val;
                    } else {
                        iss >> int_val;
                    }
                    
                    value = static_cast<uint64_t>(int_val);
                    break;
                }
                case 1: { // float
                    float float_val = std::stof(input_value);
                    std::memcpy(&value, &float_val, sizeof(float));
                    break;
                }
                case 2: { // double
                    double double_val = std::stod(input_value);
                    std::memcpy(&value, &double_val, sizeof(double));
                    break;
                }
                case 3: { // bytes (format: "AA BB CC DD")
                    std::istringstream iss(input_value);
                    std::string byte_str;
                    int byte_index = 0;
                    
                    while (iss >> byte_str && byte_index < 8) {
                        // Convert hex string to byte
                        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
                        // Place in correct position in value
                        value |= static_cast<uint64_t>(byte) << (byte_index * 8);
                        byte_index++;
                    }
                    break;
                }
            }
            
            // Apply the change
            if (freeze_value) {
                // Just update the frozen buffer
                memory_values[selected_index] = value;
                
                // Update display
                libmem::Address row_addr = address + (selected_index * sizeof(uint64_t));
                std::string line = FormatAsHex(row_addr) + ": " + 
                                  FormatHexBytes(value, sizeof(uint64_t)) + "  " +
                                  FormatAsAscii(value, sizeof(uint64_t));
                memory_lines[selected_index] = line;
                
                status_message = "Value updated (frozen)";
                return true;
            } else {
                // Write directly to memory
                libmem::Address target_addr = address + (selected_index * sizeof(uint64_t));
                try {
                    // Use template version of WriteMemory
                    libmem::WriteMemory<uint64_t>(target_addr, value);
                    
                    // Update our cached value
                    memory_values[selected_index] = value;
                    
                    // Update display
                    libmem::Address row_addr = address + (selected_index * sizeof(uint64_t));
                    std::string line = FormatAsHex(row_addr) + ": " + 
                                      FormatHexBytes(value, sizeof(uint64_t)) + "  " +
                                      FormatAsAscii(value, sizeof(uint64_t));
                    memory_lines[selected_index] = line;
                    
                    status_message = "Value updated successfully";
                    return true;
                } catch (const std::exception& e) {
                    status_message = "Failed to write memory: " + std::string(e.what());
                    return false;
                }
            }
        } catch (const std::exception& e) {
            status_message = "Error: " + std::string(e.what());
            return false;
        }
    };
    
    // Function to toggle freezing
    auto toggle_freeze = [&]() {
        freeze_value = !freeze_value;
        if (freeze_value) {
            // Copy current values to frozen buffer
            frozen_buffer = memory_values;
            status_message = "Memory values frozen";
        } else {
            status_message = "Memory values unfrozen";
        }
    };
    
    // Update thread for real-time memory watching
    std::atomic<bool> thread_running{true};
    std::thread update_thread([&]() {
        while (thread_running) {
            // Only update if not paused
            if (!paused && is_running) {
                try {
                    // Read current memory values
                    std::vector<uint64_t> current_values(memory_values.size(), 0);
                    for (size_t i = 0; i < current_values.size(); i++) {
                        libmem::Address curr_addr = address + (i * sizeof(uint64_t));
                        try {
                            current_values[i] = libmem::ReadMemory<uint64_t>(curr_addr);
                        } catch (...) {
                            // Handle failure for this address
                            current_values[i] = memory_values[i]; // Keep old value
                        }
                    }
                    
                    // If we have frozen values, write them back to memory
                    if (freeze_value) {
                        for (size_t i = 0; i < memory_values.size(); i++) {
                            libmem::Address curr_addr = address + (i * sizeof(uint64_t));
                            try {
                                // Write frozen value back to memory
                                libmem::WriteMemory<uint64_t>(curr_addr, frozen_buffer[i]);
                                // Update display for frozen memory - shows what we're enforcing
                                current_values[i] = frozen_buffer[i];
                            } catch (...) {
                                // Ignore write failures
                            }
                        }
                    }
                    
                    // Check for changes and update display
                    for (size_t i = 0; i < current_values.size(); i++) {
                        if (current_values[i] != memory_values[i]) {
                            // Value changed, update display
                            libmem::Address row_addr = address + (i * sizeof(uint64_t));
                            std::string line = FormatAsHex(row_addr) + ": " + 
                                              FormatHexBytes(current_values[i], sizeof(uint64_t)) + "  " +
                                              FormatAsAscii(current_values[i], sizeof(uint64_t));
                            memory_lines[i] = line;
                            memory_values[i] = current_values[i];
                        }
                    }
                } catch (...) {
                    // Ignore errors during update
                }
            }
            
            // Sleep to avoid excessive CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
        elements.push_back(text("Controls: (E)dit value | (P)ause | (G)o to address | (ESC) Return") | color(Color::GrayDark));
        
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
                uint64_t current_value = memory_values[selected_index];
                switch (type_index) {
                    case 0: // int64
                        edit_value = std::to_string(static_cast<int64_t>(current_value));
                        break;
                    case 1: { // float
                        float float_val;
                        std::memcpy(&float_val, &current_value, sizeof(float));
                        edit_value = std::to_string(float_val);
                        break;
                    }
                    case 2: { // double
                        double double_val;
                        std::memcpy(&double_val, &current_value, sizeof(double));
                        edit_value = std::to_string(double_val);
                        break;
                    }
                    case 3: // bytes
                        edit_value = FormatHexBytes(current_value, sizeof(uint64_t));
                        break;
                }
                
                return true;
            } else if (event == Event::Character('p') || event == Event::Character('P')) {
                // Toggle pause
                paused = !paused;
                status_message = paused ? "Watching paused" : "Watching resumed";
                return true;
            } else if (event == Event::Character('f') || event == Event::Character('F')) {
                // Toggle freeze
                toggle_freeze();
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
            // Placeholder for scanning entire process memory
            // In a real app, would need to enumerate memory regions
            return result;
        }
        
        // Perform the signature scan using the correct API
        auto result_opt = libmem::SigScan(&process, cleaned_signature.c_str(), start_address, scan_size);
        
        if (result_opt.has_value()) {
            result.success = true;
            result.address = result_opt.value();
            result.matches.push_back(result_opt.value()); // Add the match
        }
    } catch (const std::exception&) {
        // Handle exceptions
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

  // Counter for the background thread
  std::atomic<uint64_t> counter{0};
  std::atomic<bool> thread_running{true};
  
  // Start a background thread that counts up
  std::thread counter_thread([&counter, &thread_running]() {
    while (thread_running) {
      counter++;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  });

  // Dummy process list - create a larger list
  std::vector<ProcessInfo> all_processes = {
      {"chrome.exe", 1234, 5.2, 256},
      {"explorer.exe", 2345, 1.8, 128},
      {"notepad.exe", 3456, 0.5, 32},
      {"spotify.exe", 4567, 3.2, 192},
      {"discord.exe", 5678, 2.1, 160},
      {"vscode.exe", 6789, 4.5, 224},
      {"slack.exe", 7890, 1.9, 144},
      {"firefox.exe", 8901, 4.8, 240},
      {"steam.exe", 9012, 3.7, 208},
      {"outlook.exe", 1023, 2.3, 176},
      {"photoshop.exe", 2134, 6.7, 512},
      {"vlc.exe", 3245, 1.2, 64},
      {"winamp.exe", 4356, 0.8, 48},
      {"word.exe", 5467, 2.5, 128},
      {"excel.exe", 6578, 3.1, 196},
      {"powerpoint.exe", 7689, 2.8, 180},
      {"itunes.exe", 8790, 1.7, 120},
      {"skype.exe", 9801, 1.4, 112},
      {"telegram.exe", 1024, 1.1, 88},
      {"whatsapp.exe", 2135, 1.3, 96},
      {"malwarebytes.exe", 3246, 0.9, 120},
      {"avast.exe", 4357, 1.6, 156},
      {"winrar.exe", 5468, 0.3, 32},
      {"7zip.exe", 6579, 0.4, 28},
      {"cmd.exe", 7680, 0.2, 12},
      {"powershell.exe", 8791, 0.7, 88},
      {"taskmanager.exe", 9802, 1.0, 64},
  };

  // Dummy module list - create a larger list
  std::vector<ModuleInfo> all_modules = {
      {"kernel32.dll", "0x7FFE12340000", 864},
      {"ntdll.dll", "0x7FFE98760000", 1920},
      {"user32.dll", "0x7FFE43210000", 576},
      {"gdi32.dll", "0x7FFE56780000", 384},
      {"comctl32.dll", "0x7FFE76540000", 1024},
      {"msvcrt.dll", "0x7FFE32100000", 768},
      {"advapi32.dll", "0x7FFE87650000", 640},
      {"shell32.dll", "0x7FFE65430000", 2048},
      {"ws2_32.dll", "0x7FFE54320000", 320},
      {"winmm.dll", "0x7FFE21098000", 512},
      {"d3d11.dll", "0x7FFE76540000", 1536},
      {"d3dcompiler_47.dll", "0x7FFE76FF0000", 2048},
      {"dxgi.dll", "0x7FFE76570000", 896},
      {"ole32.dll", "0x7FFE76780000", 1280},
      {"combase.dll", "0x7FFE76990000", 3072},
      {"oleaut32.dll", "0x7FFE76AA0000", 1024},
      {"bcrypt.dll", "0x7FFE76BB0000", 384},
      {"cryptbase.dll", "0x7FFE76CC0000", 192},
      {"ucrtbase.dll", "0x7FFE76DD0000", 1536},
      {"sechost.dll", "0x7FFE76EE0000", 512},
      {"msvcp_win.dll", "0x7FFE76FF0000", 512},
      {"vcruntime140.dll", "0x7FFE77100000", 128},
      {"kernelbase.dll", "0x7FFE77210000", 2048},
      {"rpcrt4.dll", "0x7FFE77320000", 1024},
      {"shlwapi.dll", "0x7FFE77430000", 512},
      {"setupapi.dll", "0x7FFE77540000", 2048},
      {"cfgmgr32.dll", "0x7FFE77650000", 384},
      {"imagehlp.dll", "0x7FFE77760000", 256},
      {"psapi.dll", "0x7FFE77870000", 128},
  };

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

  // Menu selection variables
  int process_selected = 0;
  int module_selected = 0;
  bool show_process_filter = false;
  bool show_module_filter = false;

  // Memory and disassembly selection
  int memory_selected = 0;
  int disasm_selected = 0;

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

  // Input components for filtering
  Component process_filter_input = Input(&process_filter, "Filter processes...");
  Component module_filter_input = Input(&module_filter, "Filter modules...");
  
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

  // Create tab container for navigation between filter input and list
  auto process_container = Container::Vertical({
    process_filter_input,
    process_menu
  });
  
  auto module_container = Container::Vertical({
    module_filter_input,
    module_menu
  });

  // Memory and Disassembly menus - updated in the renderer
  std::vector<std::string> memory_entries;
  std::vector<std::string> disasm_entries;
  Component memory_menu = Menu(&memory_entries, &memory_selected, memory_menu_option);
  Component disasm_menu = Menu(&disasm_entries, &disasm_selected, disasm_menu_option);

  // Main container with all components
  auto main_container = Container::Vertical({
    Container::Horizontal({
      Container::Horizontal({
        process_container,
        module_container
      }),
      disasm_menu
    }),
    Container::Horizontal({
      Container::Vertical({}), // placeholder for info section
      memory_menu
    })
  });

  // By default, hide filter inputs
  process_container->SetActiveChild(process_menu);
  module_container->SetActiveChild(module_menu);

  // Create the component with event handling
  auto component = Renderer(main_container, [&] {
    Element process_section;
    Element module_section;
    
    // Process section with conditional filter display
    if (show_process_filter) {
      process_section = vbox({
        hcenter(bold(text("Filter Processes  -  (ESC) to close"))),
        separator(),
        process_filter_input->Render(),
        separator(),
        process_menu->Render() | vscroll_indicator | frame | flex,
      });
    } else {
      process_section = vbox({
        hcenter(bold(text("Processes  -  (F)ilter"))),
        separator(),
        process_menu->Render() | vscroll_indicator | frame | flex,
      });
    }
    
    // Module section with conditional filter display
    if (show_module_filter) {
      module_section = vbox({
        hcenter(bold(text("Filter Modules"))),
        separator(),
        module_filter_input->Render(),
        separator(),
        module_menu->Render() | vscroll_indicator | frame | flex,
      });
    } else {
      module_section = vbox({
        hcenter(bold(text("Modules (F)ilter"))),
        separator(),
        module_menu->Render() | vscroll_indicator | frame | flex,
      });
    }

    // Get the selected process and module (if available)
    ProcessInfo selected_process;
    if (!filtered_processes.empty() && process_selected < static_cast<int>(filtered_processes.size())) {
      selected_process = filtered_processes[process_selected];
    } else {
      selected_process = {"No process selected", 0, 0.0, 0};
    }

    ModuleInfo selected_module;
    if (!filtered_modules.empty() && module_selected < static_cast<int>(filtered_modules.size())) {
      selected_module = filtered_modules[module_selected];
    } else {
      selected_module = {"No module selected", "0x00000000", 0};
    }

    // Get current counter value
    uint64_t current_counter = counter.load();
    
    // Use fixed base address
    const uint64_t base_address = 0x7FFC0000;
    
    // Update memory menu entries
    memory_entries.clear();
    
    // Memory title
    std::string memory_title = "MEMORY INSPECTOR  -  (G)o to (P)ause (F)reeze (E)dit";
    
    // Add memory rows with fixed addresses - more rows for twice the height
    const uint64_t fixed_addresses[] = {
        0x7FFC0000,
        0x7FFC0010,
        0x7FFC0020,
        0x7FFC0030,
        0x7FFC0040,
        0x7FFC0050,
        0x7FFC0060,
        0x7FFC0070,
        0x7FFC0080,
        0x7FFC0090
    };
    
    for (int i = 0; i < 10; i++) {
        uint64_t addr = fixed_addresses[i];
        uint64_t value = current_counter + i;
        
        std::string addr_str = FormatAsHex(addr);
        std::string bytes_str = FormatHexBytes(value, 8);
        std::string ascii_str = FormatAsAscii(value, 8);
        
        // Row content with fixed spacing for menu
        std::string row = addr_str + ":  " + bytes_str + "  │ int: " + 
                         std::to_string(value) + " │ \"" + ascii_str + "\"";
        memory_entries.push_back(row);
    }
    
    // Update disassembly menu entries
    disasm_entries.clear();
    
    // Disassembly title
    std::string disasm_title = "DISASSEMBLY  -  (S)can for signatures";
    
    // Generate fake disassembly
    const uint64_t disasm_base = 0x140001000;
    auto disasm = GenerateFakeDisassembly(disasm_base, current_counter);
    
    // Add disassembly rows to menu entries
    for (const auto& instr : disasm) {
        std::string row = FormatAsHex(instr.address) + ":  " +
                         instr.bytes + "  │ " +
                         instr.mnemonic + "  " +
                         instr.operands;
        disasm_entries.push_back(row);
    }

    // Process and module info section
    auto info_section = vbox({
        text("Process Information:"),
        hbox({
            text(" CPU Usage: "),
            gauge(selected_process.cpu_usage / 10.0),
        }),
        hbox({
            text(" Memory: "),
            text(std::to_string(selected_process.memory_mb) + " MB"),
        }),
        separator(),
        text("Module Information:"),
        hbox({
            text(" Base Address: "),
            text(selected_module.base_address),
        }),
        hbox({
            text(" Size: "),
            text(std::to_string(selected_module.size_kb) + " KB"),
        }),
        separator(),
        text("Additional Information:"),
        hbox({
            text(" PID: "),
            text(std::to_string(selected_process.pid)),
        }),
        hbox({
            text(" Priority: "),
            text("Normal"),
        }),
        hbox({
            text(" Threads: "),
            text(std::to_string(4 + (current_counter % 8))),
        }),
        hbox({
            text(" Handles: "),
            text(std::to_string(120 + (current_counter % 50))),
        }),
    }) | border;

    // Selection info panels
    Element memory_info;
    if (memory_selected >= 0 && memory_selected < static_cast<int>(memory_entries.size())) {
        uint64_t addr = fixed_addresses[memory_selected];
        memory_info = vbox({
            text("Selected Memory:"),
            text(" Address: " + FormatAsHex(addr)),
            text(" Value (int): " + std::to_string(current_counter + memory_selected)),
            text(" As float: " + std::to_string(static_cast<float>(current_counter + memory_selected))),
            text(" As double: " + std::to_string(static_cast<double>(current_counter + memory_selected))),
        }) | border;
    } else {
        memory_info = text("No memory selected") | border;
    }
    
    Element disasm_info;
    if (disasm_selected >= 0 && disasm_selected < static_cast<int>(disasm_entries.size())) {
        auto& instr = disasm[disasm_selected];
        disasm_info = vbox({
            text("Selected Instruction:"),
            text(" Address: " + FormatAsHex(instr.address)),
            text(" Bytes: " + instr.bytes),
            text(" Operation: " + instr.mnemonic + " " + instr.operands),
        }) | border;
    } else {
        disasm_info = text("No instruction selected") | border;
    }

    // Create memory and disassembly section titles
    auto memory_section_title = vbox({
        bold(text(memory_title)),
        separator(),
    });
    
    auto disasm_section_title = vbox({
        bold(text(disasm_title)),
        separator(),
    });

    return vbox({
              // Top panel with menus and info - 50% of height
              hbox({
                // Left side with process and module lists - 60% of width
                hbox({
                  process_section | flex,
                  separator(),
                  module_section | flex,
                }) | size(WIDTH, GREATER_THAN, 60),
                separator(),
                // Right side with disassembly - 40% of width
                vbox({
                  disasm_section_title,
                  disasm_menu->Render() | vscroll_indicator | frame | flex,
                  disasm_info,
                }) | size(WIDTH, LESS_THAN, 40),
              }) | size(HEIGHT, GREATER_THAN, 50),
              separator(),
              // Bottom panel with memory display and info - 50% of height
              hbox({
                // Left side with info - 30% of width
                vbox({
                  info_section,
                  memory_info,
                }) | size(WIDTH, LESS_THAN, 30),
                separator(),
                // Right side with memory display - 70% of width
                vbox({
                  memory_section_title,
                  memory_menu->Render() | vscroll_indicator | frame | flex,
                }) | size(WIDTH, GREATER_THAN, 70),
              }) | size(HEIGHT, LESS_THAN, 50),
          }) | border;
  });

  // Add event handling 
  auto with_key_events = CatchEvent(component, [&](Event event) {
    if (event == Event::Character('f') || event == Event::Character('F')) {
      // Determine which side is active
      auto is_process_active = process_container->Active() || process_filter_input->Active();
      auto is_module_active = module_container->Active() || module_filter_input->Active();
      
      if (is_process_active) {
        // Toggle process filter
        show_process_filter = !show_process_filter;
        if (show_process_filter) {
          process_container->SetActiveChild(process_filter_input);
        } else {
          process_container->SetActiveChild(process_menu);
        }
        return true;
      } else if (is_module_active) {
        // Toggle module filter
        show_module_filter = !show_module_filter;
        if (show_module_filter) {
          module_container->SetActiveChild(module_filter_input);
        } else {
          module_container->SetActiveChild(module_menu);
        }
        return true;
      }
    }
    // Handle escape to exit filtering
    if (event == Event::Escape) {
      if (show_process_filter) {
        show_process_filter = false;
        process_container->SetActiveChild(process_menu);
        return true;
      }
      if (show_module_filter) {
        show_module_filter = false;
        module_container->SetActiveChild(module_menu);
        return true;
      }
    }
    
    return false;
  });

  // Create an animated component that refreshes continuously
  auto animated = Renderer(with_key_events, [&] {
    // Force a refresh
    screen.PostEvent(Event::Custom);
    return with_key_events->Render();
  });

  // Start a refresh thread to update the UI
  std::thread refresh_thread([&screen]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(33)); // ~30 FPS
      screen.PostEvent(Event::Custom);
    }
  });
  
  // Set the refresh thread to detach so it doesn't block when we exit
  refresh_thread.detach();

  // Start the main loop
  screen.Loop(animated);
  
  // Clean up the counter thread before exiting
  thread_running = false;
  if (counter_thread.joinable()) {
    counter_thread.join();
  }
}