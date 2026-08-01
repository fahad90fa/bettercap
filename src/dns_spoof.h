#pragma once
#include "types.h"
#include <thread>
#include <atomic>
#include <map>
#include <string>
#include <functional>

namespace phantom {

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} __attribute__((packed));

class DnsSpoofer {
public:
    DnsSpoofer();
    ~DnsSpoofer();

    void SetInterface(const std::string& iface);
    void SetRedirectIp(const std::string& ip);
    void AddRecord(const std::string& domain, const std::string& redirect_ip);
    void SetCallback(std::function<void(const std::string& domain,
                                         const std::string& client_ip,
                                         const std::string& resolved_ip)> cb);

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    void CaptureLoop();
    bool ParseAndRespond(const uint8_t* data, size_t len,
                          const std::string& client_ip);
    std::string ExtractDomainName(const uint8_t* data, size_t offset, size_t total_len);
    std::vector<uint8_t> BuildDnsResponse(const DnsHeader& orig_header,
                                            const std::string& domain,
                                            const std::string& redirect_ip);
    uint16_t RandomId();

    std::string interface_;
    std::string redirect_ip_;
    std::map<std::string, std::string> records_;
    std::function<void(const std::string&, const std::string&, const std::string&)> callback_;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

} // namespace phantom
