#include "device_tracker.h"
#include "logger.h"
#include "network.h"
#include <chrono>

namespace phantom {

void DeviceTracker::StartArpScan() {
    scanning_ = true;
    scan_thread_ = std::thread([this]() {
        while (scanning_) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            LOG_DEBUG("Device scanner tick");
        }
    });
}

void DeviceTracker::StopArpScan() {
    scanning_ = false;
    if (scan_thread_.joinable()) scan_thread_.join();
}

void DeviceTracker::RecordActivity(const ParsedActivity& activity, const MacAddress& mac) {
    Session::Instance().UpdateDevice(mac, [&](DeviceInfo& dev) {
        dev.last_seen = std::chrono::system_clock::now();
        dev.recent_activities.push_back(activity);
        if (dev.recent_activities.size() > 64) dev.recent_activities.erase(dev.recent_activities.begin());
    });
}

void DeviceTracker::RecordCredential(const CapturedCredential& cred, const MacAddress& mac) {
    Session::Instance().UpdateDevice(mac, [&](DeviceInfo& dev) {
        dev.captured_creds.push_back(cred);
        if (dev.captured_creds.size() > 64) dev.captured_creds.erase(dev.captured_creds.begin());
    });
}

void DeviceTracker::RecordDomainVisit(const std::string& domain, const MacAddress& mac) {
    Session::Instance().UpdateDevice(mac, [&](DeviceInfo& dev) {
        dev.visited_domains.insert(domain);
    });
}

void DeviceTracker::UpdateDeviceFromIp(const std::string& ip, const std::string& iface) {
    (void)ip;
    (void)iface;
    LOG_DEBUG("Device refresh requested");
}

} // namespace phantom
