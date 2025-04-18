#pragma once


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
#ifdef _WIN32
    #include "../LIBMEMWIN/includeWIN/libmem/libmem.hpp"
#else
    #include "../LIBMEMLIN/includeLIN/libmem/libmem.hpp"
#endif
#include "structs.h"
