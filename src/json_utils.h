#pragma once
#include "types.h"
#include <string>
#include <vector>

namespace phantom {

std::string ActivityToJson(const ParsedActivity& activity);
std::string CredentialToJson(const CapturedCredential& cred);
std::string DeviceToJson(const DeviceInfo& dev);
std::string PrintActivityRealtime(const ParsedActivity& activity);
std::string PrintCredentialRealtime(const CapturedCredential& cred);

} // namespace phantom
