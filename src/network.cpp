#include "network.h"
#include "logger.h"
#include "config.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#endif

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <chrono>

#if defined(__has_include)
#  if __has_include(<pcap/pcap.h>)
#    include <pcap/pcap.h>
#    define PHANTOM_HAS_PCAP 1
#  elif __has_include(<pcap.h>)
#    include <pcap.h>
#    define PHANTOM_HAS_PCAP 1
#  else
#    define PHANTOM_HAS_PCAP 0
#  endif
#else
#  define PHANTOM_HAS_PCAP 0
#endif

namespace phantom {

std::map<uint32_t, std::string> NetworkManager::oui_db_;
bool NetworkManager::oui_loaded_ = false;

std::vector<NetworkInterface> NetworkManager::EnumerateInterfaces() {
    std::vector<NetworkInterface> interfaces;

#ifdef _WIN32
    ULONG bufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
    if (GetAdaptersInfo(pAdapterInfo, &bufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            NetworkInterface iface;
            iface.name = pAdapter->AdapterName;
            iface.description = pAdapter->Description;
            iface.ip = pAdapter->IpAddressList.IpAddress.String;
            iface.netmask = pAdapter->IpAddressList.IpMask.String;
            iface.gateway = pAdapter->GatewayList.IpAddress.String;
            iface.mac = "";
            if (pAdapter->AddressLength == 6) {
                char mac_buf[18];
                snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                    pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                    pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);
                iface.mac = mac_buf;
            }
            iface.is_up = (pAdapter->Type == MIB_IF_TYPE_ETHERNET);
            interfaces.push_back(iface);
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
#else
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0) {
        struct ifaddrs* ifa = ifaddr;
        while (ifa) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                NetworkInterface iface;
                iface.name = ifa->ifa_name;
                iface.is_up = (ifa->ifa_flags & IFF_UP) != 0;
                iface.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;

                struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
                iface.ip = inet_ntoa(sa->sin_addr);

                if (ifa->ifa_netmask) {
                    sa = (struct sockaddr_in*)ifa->ifa_netmask;
                    iface.netmask = inet_ntoa(sa->sin_addr);
                }

                int fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (fd >= 0) {
                    struct ifreq ifr;
                    strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ);
                    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                        uint8_t* mac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
                        char mac_buf[18];
                        snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        iface.mac = mac_buf;
                    }
                    close(fd);
                }
                interfaces.push_back(iface);
            }
            ifa = ifa->ifa_next;
        }
        freeifaddrs(ifaddr);
    }

    std::ifstream route("/proc/net/route");
    std::string line;
    while (std::getline(route, line)) {
        std::istringstream iss(line);
        std::string iface_name, dest, gw;
        iss >> iface_name >> dest >> gw;
        if (dest == "00000000" && !gw.empty() && gw != "00000000") {
            uint32_t gw_addr;
            sscanf(gw.c_str(), "%x", &gw_addr);
            struct in_addr addr;
            addr.s_addr = gw_addr;
            for (auto& ifc : interfaces) {
                if (ifc.name == iface_name) {
                    ifc.gateway = inet_ntoa(addr);
                }
            }
        }
    }
#endif

    return interfaces;
}

std::optional<NetworkInterface> NetworkManager::FindInterface(const std::string& name) {
    auto interfaces = EnumerateInterfaces();
    for (auto& iface : interfaces) {
        if (iface.name == name || iface.description.find(name) != std::string::npos) {
            return iface;
        }
    }
    return std::nullopt;
}

std::optional<NetworkInterface> NetworkManager::FindInterfaceByGateway() {
    auto interfaces = EnumerateInterfaces();
    for (auto& iface : interfaces) {
        if (!iface.gateway.empty() && !iface.is_loopback) {
            return iface;
        }
    }
    return std::nullopt;
}

bool NetworkManager::SendRawPacket(const std::string& interface_name,
                                    const uint8_t* data, size_t len) {
#if PHANTOM_HAS_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        LOG_ERROR("Failed to open interface for raw send: " + std::string(errbuf));
        return false;
    }

    int result = pcap_sendpacket(handle, data, (int)len);
    pcap_close(handle);

    if (result != 0) {
        LOG_ERROR("Failed to send raw packet on " + interface_name);
        return false;
    }
    return true;
#else
    (void)interface_name;
    (void)data;
    (void)len;
    LOG_WARN("Packet sending requested but libpcap is unavailable in this environment");
    return false;
#endif
}

std::string NetworkManager::GetDefaultGateway() {
    auto iface = FindInterfaceByGateway();
    return iface ? iface->gateway : "";
}

std::string NetworkManager::GetLocalIp() {
    auto iface = FindInterfaceByGateway();
    return iface ? iface->ip : "";
}

std::string NetworkManager::GetLocalMac(const std::string& interface_name) {
    auto iface = FindInterface(interface_name);
    return iface ? iface->mac : "";
}

MacAddress NetworkManager::GetMacForIp(const std::string& interface_name,
                                        IPv4Address target_ip) {
    std::string arp_result = ArpLookup(target_ip);
    if (!arp_result.empty()) {
        return MacAddress::FromString(arp_result);
    }

#if PHANTOM_HAS_PCAP
    uint8_t packet[64] = {0};
    memset(packet, 0xFF, 6);
    auto local_mac = MacAddress::FromString(GetLocalMac(interface_name));
    memcpy(packet + 6, local_mac.bytes, 6);
    packet[12] = 0x08; packet[13] = 0x06;
    packet[14] = 0x00; packet[15] = 0x01;
    packet[16] = 0x08; packet[17] = 0x00;
    packet[18] = 0x06; packet[19] = 0x04;
    packet[20] = 0x00; packet[21] = 0x01;
    memcpy(packet + 22, local_mac.bytes, 6);
    auto local_ip = IPv4Address::FromString(GetLocalIp());
    memcpy(packet + 28, &local_ip.addr, 4);
    memset(packet + 32, 0, 6);
    memcpy(packet + 38, &target_ip.addr, 4);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface_name.c_str(), 65535, 1, 100, errbuf);
    if (!handle) return MacAddress{};

    struct bpf_program filter;
    std::string filter_str = "arp and ether dst " + local_mac.ToString();
    pcap_compile(handle, &filter, filter_str.c_str(), 1, 0);
    pcap_setfilter(handle, &filter);

    SendRawPacket(interface_name, packet, 42);

    struct pcap_pkthdr* header;
    const uint8_t* capture_data;
    int retries = 10;
    MacAddress result{};

    while (retries-- > 0) {
        if (pcap_next_ex(handle, &header, &capture_data) > 0) {
            if (capture_data[14] == 0x00 && capture_data[15] == 0x02) {
                uint32_t reply_ip;
                memcpy(&reply_ip, capture_data + 28, 4);
                if (reply_ip == target_ip.addr) {
                    memcpy(result.bytes, capture_data + 22, 6);
                    break;
                }
            }
        }
    }

    pcap_freecode(&filter);
    pcap_close(handle);
    return result;
#else
    (void)interface_name;
    (void)target_ip;
    return MacAddress{};
#endif
}

std::string NetworkManager::ArpLookup(IPv4Address ip) {
#ifdef _WIN32
    ULONG macAddrLen = 6;
    DWORD macAddr[2] = {0};
    ULONG ret = SendARP(ip.addr, 0, macAddr, &macAddrLen);
    if (ret == NO_ERROR && macAddrLen == 6) {
        uint8_t* bytes = (uint8_t*)macAddr;
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return std::string(buf);
    }
#else
    std::ifstream arp("/proc/net/arp");
    std::string line;
    while (std::getline(arp, line)) {
        std::istringstream iss(line);
        std::string ip_str, hw_type, flags, mac_str;
        iss >> ip_str >> hw_type >> flags >> mac_str;
        if (IPv4Address::FromString(ip_str) == ip && mac_str != "00:00:00:00:00:00") {
            return mac_str;
        }
    }
#endif
    return "";
}

void NetworkManager::LoadOuiDatabase(const std::string& path) {
    if (oui_loaded_) return;

    std::vector<std::string> candidates;
    if (!path.empty()) {
        candidates.push_back(path);
    } else {
        // oui.txt first (explicit local override), then whatever real
        // vendor database this machine happens to already have installed
        // — nmap's compact prefix list ships with nmap itself (almost
        // always present on a pentest distro), Wireshark's manuf needs the
        // Wireshark package specifically, and Debian's ieee-data package
        // (a common transitive dependency of tools like arp-scan/ettercap)
        // installs the raw IEEE registry. Any of these beats this file's
        // own ~30-entry hardcoded fallback list by orders of magnitude.
        candidates = {
            "oui.txt",
            "/usr/share/nmap/nmap-mac-prefixes",
            "/usr/share/wireshark/manuf",
            "/usr/local/share/wireshark/manuf",
            "/etc/manuf",
            "/usr/share/ieee-data/oui.txt",
            "/var/lib/ieee-data/oui.txt",
        };
    }

    std::ifstream file;
    std::string used_path;
    for (auto& candidate : candidates) {
        file.open(candidate);
        if (file.is_open()) { used_path = candidate; break; }
        file.clear();
    }

    if (!file.is_open()) {
        oui_loaded_ = true;
        LOG_WARN("No vendor database found (checked oui.txt, nmap-mac-prefixes, Wireshark's "
                 "manuf, and ieee-data) - vendor names will fall back to a small built-in "
                 "list. Run: sudo apt install -y wireshark-common (installs just the manuf "
                 "database, no GUI needed) to get real vendor names.");
        return;
    }

    std::string line;
    size_t loaded = 0;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        // Formats seen in the wild: "00:00:0C\tCisco\tCisco Systems, Inc"
        // (Wireshark manuf, colon-separated prefix, tab-separated names),
        // "000000 XEROX CORPORATION" (nmap-mac-prefixes, space-separated),
        // or "000000\tXerox" (plain hex prefix + tab). Either way, the
        // prefix is whatever comes before the first tab/comma/space.
        size_t field_end = line.find_first_of("\t, ");
        if (field_end == std::string::npos) continue;
        std::string prefix_field = line.substr(0, field_end);
        std::string rest = line.substr(field_end + 1);

        std::string clean_hex;
        for (char c : prefix_field) {
            if (isxdigit(static_cast<unsigned char>(c))) clean_hex += c;
            if (clean_hex.size() == 6) break;
        }
        if (clean_hex.size() != 6) continue; // not a 24-bit OUI prefix (e.g. has a /28 mask) — skip

        uint32_t oui = 0;
        sscanf(clean_hex.c_str(), "%x", &oui);

        // Prefer the long-form vendor name (Wireshark's 2nd tab field)
        // when present, otherwise use whatever's left on the line.
        size_t tab2 = rest.find('\t');
        std::string vendor = (tab2 != std::string::npos) ? rest.substr(tab2 + 1) : rest;

        while (!vendor.empty() && (vendor.back() == '\r' || vendor.back() == '\n' || vendor.back() == ' '))
            vendor.pop_back();
        size_t start = vendor.find_first_not_of(' ');
        vendor = (start == std::string::npos) ? "" : vendor.substr(start);
        if (vendor.empty()) continue;

        oui_db_[oui] = vendor;
        loaded++;
    }

    oui_loaded_ = true;
    if (loaded > 0) {
        LOG_SUCCESS("Loaded " + std::to_string(loaded) + " vendor entries from " + used_path);
    } else {
        LOG_WARN("Vendor database at " + used_path + " had no parseable entries "
                 "- vendor names will fall back to a small built-in list");
    }
}

std::string NetworkManager::LookupVendor(const MacAddress& mac) {
    if (!oui_loaded_) LoadOuiDatabase();
    uint32_t oui = (mac.bytes[0] << 16) | (mac.bytes[1] << 8) | mac.bytes[2];
    auto it = oui_db_.find(oui);
    if (it != oui_db_.end()) return it->second;

    uint16_t short_oui = (mac.bytes[0] << 8) | mac.bytes[1];
    if (short_oui == 0x000C || short_oui == 0x001A || short_oui == 0x001B) return "Apple";
    if (short_oui == 0x3C06 || short_oui == 0xA4B1 || short_oui == 0x7CD1) return "Apple";
    if (short_oui == 0xDC2B || short_oui == 0x4C32 || short_oui == 0xAC87) return "Apple";
    if (short_oui == 0xA0CB || short_oui == 0x58E2 || short_oui == 0x28F0) return "Apple";
    if (mac.bytes[0] == 0x00 && mac.bytes[1] == 0x1A) return "Apple";
    if (mac.bytes[0] == 0x28 && mac.bytes[1] == 0xCF) return "Apple";
    if (mac.bytes[0] == 0xF0 && mac.bytes[1] == 0x18) return "Apple";
    if (short_oui == 0xB474 || short_oui == 0xD4F4 || short_oui == 0x48DB) return "Samsung";
    if (short_oui == 0x9C3A || short_oui == 0xA04E || short_oui == 0xE4BE) return "Samsung";
    if (short_oui == 0x40D3 || short_oui == 0x6063 || short_oui == 0x7844) return "Samsung";
    if (short_oui == 0xD8BB || short_oui == 0x50D5 || short_oui == 0xEC1F) return "Samsung";
    if (short_oui == 0x5C51 || short_oui == 0x88E0 || short_oui == 0xB0F1) return "Xiaomi";
    if (short_oui == 0x7811 || short_oui == 0x9C99 || short_oui == 0x0C1A) return "Xiaomi";
    if (short_oui == 0x244B || short_oui == 0x64A2 || short_oui == 0x98F5) return "Xiaomi";
    if (short_oui == 0x8C9E || short_oui == 0x28E3 || short_oui == 0x50EB) return "OnePlus";
    if (short_oui == 0xF8A9 || short_oui == 0x94E1 || short_oui == 0x2CF4) return "Huawei";
    if (short_oui == 0x2082 || short_oui == 0xCC96 || short_oui == 0xE019) return "Huawei";
    if (short_oui == 0x704D || short_oui == 0xB827 || short_oui == 0xA0D3) return "Espressif (IoT)";
    if (short_oui == 0x30AE || short_oui == 0x2404 || short_oui == 0xBCDD) return "Espressif (IoT)";
    if (short_oui == 0x5C53 || short_oui == 0x7CD1 || short_oui == 0x3C06) return "Intel";
    if (short_oui == 0x0050 || short_oui == 0x0060 || short_oui == 0x001E) return "Intel";
    if (short_oui == 0xF8B1 || short_oui == 0xB4D5 || short_oui == 0x2CBE) return "Qualcomm";
    if (short_oui == 0x9CB6 || short_oui == 0x5A73 || short_oui == 0x843A) return "Realtek";

    return "Unknown";
}

std::vector<std::pair<IPv4Address, MacAddress>> NetworkManager::ScanSubnet(
        const std::string& interface_name, int timeout_ms) {
    std::vector<std::pair<IPv4Address, MacAddress>> results;
#if PHANTOM_HAS_PCAP
    auto iface = FindInterface(interface_name);
    if (!iface || iface->ip.empty() || iface->netmask.empty() || iface->mac.empty()) {
        LOG_ERROR("Cannot scan subnet: interface has no usable IPv4 address");
        return results;
    }

    unsigned int ip_o[4], mask_o[4];
    if (sscanf(iface->ip.c_str(), "%u.%u.%u.%u", &ip_o[0], &ip_o[1], &ip_o[2], &ip_o[3]) != 4 ||
        sscanf(iface->netmask.c_str(), "%u.%u.%u.%u", &mask_o[0], &mask_o[1], &mask_o[2], &mask_o[3]) != 4) {
        return results;
    }

    uint32_t ip_val = (ip_o[0] << 24) | (ip_o[1] << 16) | (ip_o[2] << 8) | ip_o[3];
    uint32_t mask_val = (mask_o[0] << 24) | (mask_o[1] << 16) | (mask_o[2] << 8) | mask_o[3];
    uint32_t network_val = ip_val & mask_val;
    uint32_t broadcast_val = network_val | ~mask_val;

    if (broadcast_val <= network_val + 1 || (broadcast_val - network_val) > 4094) {
        LOG_WARN("Subnet scan skipped: need a /20 network or smaller");
        return results;
    }

    MacAddress local_mac = MacAddress::FromString(iface->mac);
    IPv4Address local_ip = IPv4Address::FromString(iface->ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface_name.c_str(), 65535, 1, 50, errbuf);
    if (!handle) {
        LOG_ERROR("Failed to open interface for subnet scan: " + std::string(errbuf));
        return results;
    }

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "arp", 1, 0) == 0) {
        pcap_setfilter(handle, &filter);
        pcap_freecode(&filter);
    }

    for (uint32_t h = network_val + 1; h < broadcast_val; ++h) {
        std::string target_ip_str =
            std::to_string((h >> 24) & 0xFF) + "." + std::to_string((h >> 16) & 0xFF) + "." +
            std::to_string((h >> 8) & 0xFF) + "." + std::to_string(h & 0xFF);
        IPv4Address target_ip = IPv4Address::FromString(target_ip_str);
        if (target_ip.addr == local_ip.addr) continue;

        uint8_t packet[42] = {0};
        memset(packet, 0xFF, 6);
        memcpy(packet + 6, local_mac.bytes, 6);
        packet[12] = 0x08; packet[13] = 0x06;
        packet[14] = 0x00; packet[15] = 0x01;
        packet[16] = 0x08; packet[17] = 0x00;
        packet[18] = 0x06;
        packet[19] = 0x04;
        packet[20] = 0x00; packet[21] = 0x01;
        memcpy(packet + 22, local_mac.bytes, 6);
        memcpy(packet + 28, &local_ip.addr, 4);
        memset(packet + 32, 0, 6);
        memcpy(packet + 38, &target_ip.addr, 4);

        pcap_sendpacket(handle, packet, sizeof(packet));
    }

    std::map<uint32_t, MacAddress> found;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    while (std::chrono::steady_clock::now() < deadline) {
        struct pcap_pkthdr* header;
        const uint8_t* data;
        int rc = pcap_next_ex(handle, &header, &data);
        if (rc <= 0) continue;
        if (header->caplen < 42) continue;
        if (data[12] != 0x08 || data[13] != 0x06) continue;
        if (data[20] != 0x00 || data[21] != 0x02) continue; // ARP reply

        uint32_t reply_ip;
        memcpy(&reply_ip, data + 28, 4);
        if (found.find(reply_ip) == found.end()) {
            MacAddress mac{};
            memcpy(mac.bytes, data + 22, 6);
            found[reply_ip] = mac;
        }
    }

    pcap_close(handle);

    results.reserve(found.size());
    for (auto& [ip_addr, mac] : found) {
        IPv4Address ip{};
        ip.addr = ip_addr;
        results.emplace_back(ip, mac);
    }
#else
    (void)interface_name;
    (void)timeout_ms;
    LOG_WARN("Subnet scan requested but libpcap is unavailable in this environment");
#endif
    return results;
}

} // namespace phantom
