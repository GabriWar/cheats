#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>

#ifdef _WIN32
    #include "LIBMEMWIN/includeWIN/libmem/libmem.h"
#else
    #include "LIBMEMLIN/includeLIN/libmem/libmem.h"
#endif

using namespace ftxui;

// Callback function to list processes and store them in a map
lm_bool_t ListProcessesCallback(lm_process_t* process, lm_void_t* arg) {
    auto* process_map = static_cast<std::map<lm_pid_t, std::string>*>(arg);
    (*process_map)[process->pid] = process->name;
    return LM_TRUE; // Continue enumeration
}

Component Window(std::string title, Component component) {
    return Renderer(component, [component, title] {
        return window(text(title), component->Render()) | flex;
    });
}

int main() {
    // Create the screen first
    auto screen = ScreenInteractive::Fullscreen();

    // Create a map to store processes
    std::map<lm_pid_t, std::string> process_map;
    
    // Enumerate processes
    LM_EnumProcesses(ListProcessesCallback, &process_map);

    // Create menu entries for processes
    std::vector<std::string> process_entries;
    for (const auto& [pid, name] : process_map) {
        process_entries.push_back("[" + std::to_string(pid) + "] " + name);
    }

    // Create menu entries for actions
    std::vector<std::string> action_entries = {
        "Scan Memory",
        "Read Memory",
        "Write Memory",
        "List Modules",
        "Scan Modules"
    };

    // Create menu entries for display options
    std::vector<std::string> display_entries = {
        "Hex",
        "Decimal",
        "Float",
        "Bytes"
    };

    // Menu selections
    int menu_selected[] = {0, 0, 0};
    int menu_selected_global = 0;

    // Create menus
    auto process_menu = Window("Process List", Menu(&process_entries, &menu_selected[0]));
    auto action_menu = Window("Actions", Menu(&action_entries, &menu_selected[1]));
    auto display_menu = Window("Display Options", Menu(&display_entries, &menu_selected[2]));

    // Create vertical menu container
    auto menu_global = Container::Vertical(
        {
            process_menu,
            action_menu,
            display_menu
        },
        &menu_selected_global
    );

    // Create info panel
    auto info = Renderer([&] {
        int g = menu_selected_global;
        std::string value;
        if (g == 0 && !process_entries.empty()) {
            value = process_entries[menu_selected[0]];
        } else if (g == 1) {
            value = action_entries[menu_selected[1]];
        } else if (g == 2) {
            value = display_entries[menu_selected[2]];
        }

        return window(text("Information"), 
            vbox({
                text("Selected Menu: " + std::to_string(g)),
                text("Process Selection: " + std::to_string(menu_selected[0])),
                text("Action Selection: " + std::to_string(menu_selected[1])),
                text("Display Selection: " + std::to_string(menu_selected[2])),
                text("Selected Value: " + value),
                text(""),
                text("Use arrow keys to navigate"),
                text("Enter to select"),
                text("Tab to switch menus"),
                text("q to quit")
            })) | flex;
    });

    // Create refresh button
    auto refresh_button = Button("Refresh", [&] {
        process_map.clear();
        LM_EnumProcesses(ListProcessesCallback, &process_map);
        process_entries.clear();
        for (const auto& [pid, name] : process_map) {
            process_entries.push_back("[" + std::to_string(pid) + "] " + name);
        }
    });

    // Create exit button
    auto exit_button = Button("Exit", [&screen] { screen.Exit(); });

    // Create button container
    auto buttons = Container::Horizontal({
        refresh_button,
        exit_button
    });

    auto buttons_renderer = Renderer(buttons, [&] {
        return hbox({
            refresh_button->Render(),
            text(" "),
            exit_button->Render()
        });
    });

    // Create main layout
    auto global = Container::Vertical({
        Container::Horizontal({
            menu_global,
            info
        }),
        buttons_renderer
    });

    // Run the UI
    screen.Loop(global);

    return 0;
} 