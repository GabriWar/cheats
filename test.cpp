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
    
    auto renderer = Renderer(container, [&] {
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
    
    screen.Loop(renderer);
    return disasm_success;
}

/**
 * Continuously watch a memory region and display its value in various formats
 * 
 * @param process The process to read memory from
 * @param address The address to monitor
 * @param size The size of the memory region to monitor (defaults to 16 bytes)
 * @return true if watching was completed successfully
 */
bool watch_memory_region(const libmem::Process& process, libmem::Address address, size_t size = 16) {
    // Setup for terminal display
    auto screen = ScreenInteractive::TerminalOutput();
    
    // Data for the UI
    std::vector<uint8_t> memory_buffer(size, 0);
    std::string status_message = "Watching memory at address: 0x" + std::to_string(address);
    std::string hex_representation;
    std::string int32_value;
    std::string uint32_value;
    std::string float_value;
    std::string double_value;
    std::string string_value;
    int frame_count = 0;
    bool read_success = false;
    
    // Flag to control the refresh thread - using shared_ptr for safe access
    std::shared_ptr<std::atomic<bool>> should_quit = std::make_shared<std::atomic<bool>>(false);
    
    // Create a component that reads and displays memory values periodically
    auto component = Renderer([&] {
        // Update memory values on each render
        size_t bytes_read = libmem::ReadMemory(&process, address, memory_buffer.data(), size);
        read_success = (bytes_read == size);
        frame_count++;
        
        // Format the memory for display in different formats
        if (read_success) {
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
            
            status_message = "Memory watch active - refresh #" + std::to_string(frame_count);
        } else {
            status_message = "Failed to read memory at address 0x" + std::to_string(address);
        }
        
        // Module information for display
        std::string address_info = "Address: 0x" + std::to_string(address);
        
        // Create the UI elements
        Elements value_elements = {
            text(" Memory values:") | bold | color(Color::Yellow),
            text(" "),
            hbox(text(" Hex bytes:    "), text(hex_representation) | bold),
            hbox(text(" Int32:        "), text(int32_value) | bold),
            hbox(text(" UInt32:       "), text(uint32_value) | bold),
            hbox(text(" Float:        "), text(float_value) | bold),
            hbox(text(" Double:       "), text(double_value) | bold),
            hbox(text(" ASCII string: "), text(string_value) | bold),
        };
        
        // Instructions
        Elements instructions_elements = {
            text(" Instructions:") | bold | color(Color::Yellow),
            text(" "),
            text(" Press Q or Esc to quit the memory watch")
        };
        
        // Main document structure
        return vbox({
            text("Memory Watch") | bold | color(Color::Blue) | center,
            text(address_info) | color(Color::Cyan) | center,
            separator(),
            text(" " + status_message) | color(read_success ? Color::Green : Color::Red),
            separator(),
            vbox(value_elements),
            separator(),
            vbox(instructions_elements)
        }) | border;
    });

    // Add event handling for quitting
    component |= CatchEvent([&, should_quit](Event event) {
        // Quit on Escape or Q key
        if (event.is_character() && (event.character() == "q" || event.character() == "Q")) {
            *should_quit = true;
            screen.ExitLoopClosure()();
            return true;
        }
        
        if (event == Event::Escape) {
            *should_quit = true;
            screen.ExitLoopClosure()();
            return true;
        }
        
        return false;  // Pass other events through
    });
    
    // Store the thread in a shared_ptr so we can safely join it later
    std::shared_ptr<std::thread> refresh_thread = std::make_shared<std::thread>(
        [should_quit, screen_ptr = std::addressof(screen)]() {
            while (!*should_quit) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 10 times per second
                
                // Only post events if not quitting
                if (!*should_quit) {
                    try {
                        // Use a weak pointer to make sure we don't call methods on a destroyed screen
                        if (screen_ptr) {
                            screen_ptr->Post([]() {
                                // Request a new animation frame but don't refer to screen directly
                                animation::RequestAnimationFrame();
                            });
                        }
                    } catch (...) {
                        // Safely ignore any exceptions during shutdown
                        break;
                    }
                }
            }
        }
    );
    
    // Run the main loop (this will block until Exit is called)
    screen.Loop(component);
    
    // Signal the thread to quit
    *should_quit = true;
    
    // Safely join the thread to ensure it's properly terminated before we exit
    if (refresh_thread && refresh_thread->joinable()) {
        refresh_thread->join();
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
 * [WIP] Enter a specific memory address to examine
 * 
 * @param process The process to examine
 * @param module Optional module context
 */
void enter_memory_address(const libmem::Process& process, const std::optional<libmem::Module>& module = std::nullopt) {
    // Create a fullscreen terminal
    auto screen = ScreenInteractive::Fullscreen();
    
    std::cout << "Enter memory address for " << process.name;
    if (module.has_value()) {
        std::cout << " (module: " << module->name << ")";
    }
    std::cout << "..." << std::endl;
    
    // TODO: Implement memory address examination functionality
    std::cout << "Memory address examination not yet implemented." << std::endl;
    std::cout << "Press Enter to continue..." << std::endl;
    std::cin.get();
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