#pragma once
#include "types.h"
#include <string>
#include <atomic>
#include <thread>

namespace phantom {

class DeviceTracker {
public:
    static DeviceTracker& Instance() {
        static DeviceTracker tracker;
        return tracker;
    }

    void StartArpScan();
    void StopArpScan();
    bool IsScanning() const { return scanning_; }
    void PrintTable() const;

    void RecordActivity(const ParsedActivity& activity, const MacAddress& mac);
    void RecordCredential(const CapturedCredential& cred, const MacAddress& mac);
    void RecordDomainVisit(const std::string& domain, const MacAddress& mac);
    void UpdateDeviceFromIp(const std::string& ip, const std::string& iface);

private:
    DeviceTracker() = default;
    void RunSweep();

    std::atomic<bool> scanning_{false};
    std::thread scan_thread_;
};

} // namespace phantom
