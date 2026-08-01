#include "device_tracker.h"
#include "logger.h"
#include "network.h"
#include <chrono>
#include <iostream>
#include <iomanip>

namespace phantom {

namespace {
constexpr int kRescanIntervalSeconds = 20;
}

void DeviceTracker::StartArpScan() {
    if (scanning_) return;
    scanning_ = true;
    scan_thread_ = std::thread([this]() {
        while (scanning_) {
            RunSweep();
            if (!scanning_) break;
            PrintTable();
            for (int waited = 0; waited < kRescanIntervalSeconds && scanning_; ++waited) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    });
}

void DeviceTracker::StopArpScan() {
    scanning_ = false;
    if (scan_thread_.joinable()) scan_thread_.join();
}

void DeviceTracker::RunSweep() {
    const std::string iface = Session::Instance().config.interface_name;
    if (iface.empty()) {
        LOG_WARN("Device scan requested but no interface is configured");
        return;
    }

    LOG_INFO("Scanning " + iface + " for live hosts...");
    auto hosts = NetworkManager::ScanSubnet(iface);

    IPv4Address gateway_ip = Session::Instance().config.gateway_ip;
    IPv4Address local_ip = Session::Instance().config.local_ip;

    for (auto& [ip, mac] : hosts) {
        Session::Instance().UpdateDevice(mac, [&](DeviceInfo& dev) {
            auto now = std::chrono::system_clock::now();
            if (dev.first_seen.time_since_epoch().count() == 0) dev.first_seen = now;
            dev.last_seen = now;
            dev.mac = mac;
            dev.ip = ip;
            dev.vendor = NetworkManager::LookupVendor(mac);
            dev.is_gateway = (ip == gateway_ip);
            dev.is_self = (ip == local_ip);
            dev.active = true;
        });
    }

    LOG_SUCCESS("Scan complete — " + std::to_string(hosts.size()) + " host(s) responded");
}

void DeviceTracker::PrintTable() const {
    Session& session = Session::Instance();
    std::lock_guard<std::mutex> lock(session.devices_mtx);

    if (session.devices.empty()) {
        std::cout << "\nno devices discovered yet\n" << std::endl;
        return;
    }

    std::cout << "\n" << std::left
               << std::setw(17) << "IP"
               << std::setw(20) << "MAC"
               << std::setw(22) << "Vendor"
               << "Flags" << "\n";
    std::cout << std::string(70, '-') << "\n";

    for (const auto& [mac, dev] : session.devices) {
        std::string flags;
        if (dev.is_self) flags += "[self] ";
        if (dev.is_gateway) flags += "[gateway] ";
        if (dev.is_target) flags += "[target] ";

        std::cout << std::left
                   << std::setw(17) << dev.ip.ToString()
                   << std::setw(20) << mac.ToString()
                   << std::setw(22) << (dev.vendor.empty() ? "-" : dev.vendor)
                   << flags << "\n";
    }
    std::cout << std::endl;
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
