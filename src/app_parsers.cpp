#include "app_parsers.h"
#include "dpi_engine.h"

namespace phantom {

ParsedActivity AppParsers::Parse(const HttpTransaction& txn) {
    return DpiEngine::Instance().AnalyzeTransaction(txn);
}

} // namespace phantom
