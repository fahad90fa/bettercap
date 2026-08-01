#include "wifi_tools.h"
#include "logger.h"
#include <cstring>
#include <thread>

namespace phantom {

bool WifiTools::EnableMonitorMode(const std::string& iface) {
    LOG_WARN("Monitor mode requested for " + iface + " but is not available in this environment");
    return false;
}

bool WifiTools::DisableMonitorMode(const std::string& iface) {
    (void)iface;
    return true;
}

bool WifiTools::StartChannelHop(const std::string& iface) {
    (void)iface;
    return true;
}

bool WifiTools::SendDeauth(const std::string& iface, const std::string& target_mac,
                           const std::string& bssid, int count) {
    (void)iface; (void)target_mac; (void)bssid; (void)count;
    return true;
}

bool WifiTools::StartProbeCapture(const std::string& iface) {
    (void)iface;
    return true;
}

} // namespace phantom
