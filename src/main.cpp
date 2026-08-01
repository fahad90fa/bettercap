#include "logger.h"
#include "types.h"
#include "config.h"
#include "network.h"
#include "arp_spoof.h"
#include "dns_spoof.h"
#include "proxy.h"
#include "device_tracker.h"
#include "dpi_engine.h"
#include "json_utils.h"
#include <iostream>
#include <string>
#include <thread>

using namespace phantom;

int main(int argc, char** argv) {
    Logger::Instance().Init(LOG_DIR);
    LOG_INFO("PHANTOM booted");

    Session::Instance().running = true;

    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--arp") {
                LOG_INFO("ARP mode requested");
            } else if (arg == "--dns") {
                LOG_INFO("DNS mode requested");
            } else if (arg == "--proxy") {
                LOG_INFO("Proxy mode requested");
            } else if (arg == "--dpi") {
                LOG_INFO("DPI mode requested");
            } else if (arg == "--scan") {
                LOG_INFO("Scan mode requested");
            }
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    LOG_SUCCESS("PHANTOM ready");
    return 0;
}
