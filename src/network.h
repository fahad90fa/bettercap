#pragma once
#include "types.h"
#include <vector>
#include <string>
#include <optional>
#include <map>

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

private:
    static std::map<uint32_t, std::string> oui_db_;
    static bool oui_loaded_;
};

} // namespace phantom
