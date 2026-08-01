#pragma once
#include "types.h"

namespace phantom {

class AppParsers {
public:
    static ParsedActivity Parse(const HttpTransaction& txn);
};

} // namespace phantom
