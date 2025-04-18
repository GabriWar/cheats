#pragma once

#include <vector>
#include <optional>

#ifdef _WIN32
    #include "../LIBMEMWIN/includeWIN/libmem/libmem.hpp"
#else
    #include "../LIBMEMLIN/includeLIN/libmem/libmem.hpp"
#endif

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