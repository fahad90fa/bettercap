#pragma once
#include <string>
#include <vector>

namespace phantom {

class WifiTools {
public:
    static WifiTools& Instance() {
        static WifiTools w;
        return w;
    }

    bool EnableMonitorMode(const std::string& iface);
    bool DisableMonitorMode(const std::string& iface);
    bool StartChannelHop(const std::string& iface);
    bool SendDeauth(const std::string& iface, const std::string& target_mac,
                    const std::string& bssid, int count = 5);
    bool StartProbeCapture(const std::string& iface);

private:
    WifiTools() = default;
};

} // namespace phantom
