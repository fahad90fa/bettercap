#include "logger.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace phantom {
// Logger implementation is header-only via inline methods and macros
// This file exists for the build system and future expansion
} // namespace phantom
