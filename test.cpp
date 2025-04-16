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

int main() {
    // Create the screen first
    auto screen = ScreenInteractive::Fullscreen();

    // Create a map to store processes
    std::map<lm_pid_t, std::string> process_map;
    
    // Enumerate processes
    LM_EnumProcesses(ListProcessesCallback, &process_map);

    // Create table data
    std::vector<std::vector<std::string>> table_data = {
        {"PID", "Process Name", "Path"}
    };

    // Add processes to table data
    for (const auto& [pid, name] : process_map) {
        table_data.push_back({
            std::to_string(pid),
            name,
            "N/A"  // Path information would need additional API calls
        });
    }

    // Create table
    auto table = Table(table_data);

    // Style the table
    table.SelectAll().Border(LIGHT);
    table.SelectColumn(0).Border(LIGHT);
    table.SelectRow(0).Decorate(bold);
    table.SelectRow(0).SeparatorVertical(LIGHT);
    table.SelectRow(0).Border(DOUBLE);

    // Add alternating row colors
    auto content = table.SelectRows(1, -1);
    content.DecorateCellsAlternateRow(color(Color::Blue), 3, 0);
    content.DecorateCellsAlternateRow(color(Color::Cyan), 3, 1);
    content.DecorateCellsAlternateRow(color(Color::White), 3, 2);

    // Create buttons
    int selected = 0;
    auto refresh_button = Button("Refresh", [&] {
        process_map.clear();
        LM_EnumProcesses(ListProcessesCallback, &process_map);
        
        table_data.clear();
        table_data.push_back({"PID", "Process Name", "Path"});
        
        for (const auto& [pid, name] : process_map) {
            table_data.push_back({
                std::to_string(pid),
                name,
                "N/A"
            });
        }
        
        table = Table(table_data);
        // Reapply styling
        table.SelectAll().Border(LIGHT);
        table.SelectColumn(0).Border(LIGHT);
        table.SelectRow(0).Decorate(bold);
        table.SelectRow(0).SeparatorVertical(LIGHT);
        table.SelectRow(0).Border(DOUBLE);
        
        auto content = table.SelectRows(1, -1);
        content.DecorateCellsAlternateRow(color(Color::Blue), 3, 0);
        content.DecorateCellsAlternateRow(color(Color::Cyan), 3, 1);
        content.DecorateCellsAlternateRow(color(Color::White), 3, 2);
    });

    auto exit_button = Button("Exit", [&] { screen.Exit(); });

    // Create layout
    auto table_renderer = Renderer([&] {
        return table.Render();
    });

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

    auto main_component = Container::Vertical({
        table_renderer,
        buttons_renderer
    });

    // Run the UI
    screen.Loop(main_component);

    return 0;
} 