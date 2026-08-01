#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <mutex>
#include <memory>
#include <cstdint>
#include <atomic>
#include <functional>
#include <cstdio>
#include <cstring>

namespace phantom {

struct MacAddress {
    uint8_t bytes[6];

    std::string ToString() const {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return std::string(buf);
    }

    bool operator<(const MacAddress& o) const {
        return memcmp(bytes, o.bytes, 6) < 0;
    }

    bool operator==(const MacAddress& o) const {
        return memcmp(bytes, o.bytes, 6) == 0;
    }

    bool IsBroadcast() const {
        return bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF &&
               bytes[3] == 0xFF && bytes[4] == 0xFF && bytes[5] == 0xFF;
    }

    bool IsZero() const {
        return bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 &&
               bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0;
    }

    static MacAddress FromString(const std::string& s) {
        MacAddress mac{};
        unsigned int b[6];
        if (sscanf(s.c_str(), "%X:%X:%X:%X:%X:%X",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6 ||
            sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
            for (int i = 0; i < 6; i++) mac.bytes[i] = (uint8_t)b[i];
        }
        return mac;
    }
};

struct IPv4Address {
    uint32_t addr = 0;

    std::string ToString() const {
        return std::to_string((addr >> 0) & 0xFF) + "." +
               std::to_string((addr >> 8) & 0xFF) + "." +
               std::to_string((addr >> 16) & 0xFF) + "." +
               std::to_string((addr >> 24) & 0xFF);
    }

    bool operator<(const IPv4Address& o) const { return addr < o.addr; }
    bool operator==(const IPv4Address& o) const { return addr == o.addr; }

    static IPv4Address FromString(const std::string& s) {
        IPv4Address ip{};
        unsigned int a, b, c, d;
        if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            ip.addr = (d << 24) | (c << 16) | (b << 8) | a;
        }
        return ip;
    }
};

enum class AppType {
    UNKNOWN, INSTAGRAM, YOUTUBE, FACEBOOK, TWITTER, TIKTOK,
    WHATSAPP, TELEGRAM, DISCORD, REDDIT, NETFLIX, SPOTIFY,
    GENERIC_HTTP, GENERIC_HTTPS, DNS
};

enum class ActivityType {
    UNKNOWN, VIEWING_REEL, VIEWING_STORY, VIEWING_POST, VIEWING_VIDEO,
    WATCHING_LIVE, BROWSING_FEED, SENDING_MESSAGE, MAKING_CALL,
    SEARCHING, PROFILE_VIEW, LIKING, COMMENTING, SHARING,
    STREAMING_MUSIC, STREAMING_VIDEO, GENERAL_BROWSE,
    LOGIN, AUTH_TOKEN, FILE_DOWNLOAD, API_CALL
};

std::string AppTypeToString(AppType t);
std::string ActivityTypeToString(ActivityType t);
AppType DetectAppFromDomain(const std::string& host);

struct ParsedActivity {
    AppType app = AppType::UNKNOWN;
    ActivityType activity = ActivityType::UNKNOWN;
    std::string app_label;
    std::string activity_label;
    std::string title;
    std::string url;
    std::string page_url;
    std::string content_id;
    std::string username;
    std::string user_profile_url;
    std::string thumbnail_url;
    std::string description;
    std::string raw_api_path;
    std::map<std::string, std::string> extra_fields;
    std::chrono::system_clock::time_point timestamp;
};

struct CapturedCredential {
    std::string service;
    std::string credential_type;
    std::string username;
    std::string password;
    std::string token;
    std::string cookies;
    std::string url;
    std::string method;
    std::chrono::system_clock::time_point timestamp;
};

struct HttpTransaction {
    std::string client_ip;
    std::string method;
    std::string host;
    std::string path;
    std::string full_url;
    std::string user_agent;
    std::string referer;
    std::string cookie;
    std::string auth_header;
    std::string request_content_type;
    std::string request_body;
    int response_code = 0;
    std::string response_content_type;
    std::string response_body;
    std::map<std::string, std::string> request_headers;
    std::map<std::string, std::string> response_headers;
    bool is_https = false;
    std::chrono::system_clock::time_point start_time;
};

struct DeviceInfo {
    MacAddress mac;
    IPv4Address ip;
    std::string hostname;
    std::string vendor;
    std::string os_guess;
    std::string device_type;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    uint64_t bytes_sent = 0;
    uint64_t bytes_recv = 0;
    int connection_count = 0;
    std::vector<ParsedActivity> recent_activities;
    std::vector<CapturedCredential> captured_creds;
    std::set<std::string> visited_domains;
    std::set<std::string> detected_apps;
    bool is_gateway = false;
    bool is_self = false;
    bool is_target = false;
    bool active = true;
};

struct ArpEntry {
    IPv4Address ip;
    MacAddress mac;
    bool resolved = false;
};

struct SessionConfig {
    std::string interface_name;
    IPv4Address gateway_ip;
    MacAddress gateway_mac;
    IPv4Address local_ip;
    MacAddress local_mac;
    std::string network_cidr;
    std::vector<IPv4Address> target_ips;
    std::vector<MacAddress> target_macs;
    bool arp_spoof_enabled = false;
    bool dns_spoof_enabled = false;
    bool proxy_enabled = false;
    bool wifi_deauth_enabled = false;
    bool dpi_enabled = true;
    bool credential_harvest_enabled = true;
    bool device_tracking_enabled = true;
    uint16_t proxy_port = 8080;
    std::string dns_redirect_ip;
    std::map<std::string, std::string> dns_records;
};

class Session {
public:
    static Session& Instance() {
        static Session s;
        return s;
    }

    SessionConfig config;
    std::map<MacAddress, DeviceInfo> devices;
    std::map<IPv4Address, ArpEntry> arp_table;
    std::vector<ParsedActivity> activity_feed;
    std::vector<CapturedCredential> credential_store;
    std::atomic<bool> running{false};
    std::mutex devices_mtx;
    std::mutex arp_mtx;
    std::mutex activity_mtx;
    std::mutex cred_mtx;

    void AddActivity(const ParsedActivity& activity) {
        std::lock_guard<std::mutex> lock(activity_mtx);
        activity_feed.push_back(activity);
        if (activity_feed.size() > 10000) {
            activity_feed.erase(activity_feed.begin());
        }
    }

    void AddCredential(const CapturedCredential& cred) {
        std::lock_guard<std::mutex> lock(cred_mtx);
        credential_store.push_back(cred);
    }

    void UpdateDevice(const MacAddress& mac, std::function<void(DeviceInfo&)> updater) {
        std::lock_guard<std::mutex> lock(devices_mtx);
        auto& dev = devices[mac];
        updater(dev);
    }

    DeviceInfo GetDevice(const MacAddress& mac) {
        std::lock_guard<std::mutex> lock(devices_mtx);
        if (devices.count(mac)) return devices[mac];
        return DeviceInfo{};
    }

private:
    Session() = default;
};

} // namespace phantom
