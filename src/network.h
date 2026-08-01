#pragma once
#include "types.h"
#include <vector>
#include <string>
#include <optional>
#include <map>
#include <utility>

namespace phantom {

struct NetworkInterface {
    std::string name;
    std::string description;
    std::string ip;
    std::string netmask;
    std::string gateway;
    std::string mac;
    bool is_up = false;
    bool is_loopback = false;
};

class NetworkManager {
public:
    static std::vector<NetworkInterface> EnumerateInterfaces();
    static std::optional<NetworkInterface> FindInterface(const std::string& name);
    static std::optional<NetworkInterface> FindInterfaceByGateway();
    static bool SendRawPacket(const std::string& interface_name,
                              const uint8_t* data, size_t len);
    static MacAddress GetMacForIp(const std::string& interface_name,
                                   IPv4Address target_ip);
    static std::string ArpLookup(IPv4Address ip);
    static std::string GetDefaultGateway();
    static std::string GetLocalIp();
    static std::string GetLocalMac(const std::string& interface_name);

    static std::string LookupVendor(const MacAddress& mac);
    static void LoadOuiDatabase(const std::string& path = "");

    // ARP-sweeps every host in the interface's local subnet (max /20) and
    // returns everyone who replied. Blocks for roughly timeout_ms.
    static std::vector<std::pair<IPv4Address, MacAddress>> ScanSubnet(
        const std::string& interface_name, int timeout_ms = 3000);

private:
    static std::map<uint32_t, std::string> oui_db_;
    static bool oui_loaded_;
};

} // namespace phantom
