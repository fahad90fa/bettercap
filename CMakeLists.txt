cmake_minimum_required(VERSION 3.21)
project(PHANTOM LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

set(PACKET_LIB "")
if(WIN32)
    set(PACKET_LIB "wpcap" "Packet" "ws2_32" "Iphlpapi")
    include_directories("C:/Npcap/include")
    link_directories("C:/Npcap/lib/x64")
else()
    if(PkgConfig_FOUND)
        pkg_check_modules(PCAP QUIET libpcap)
        if(PCAP_FOUND)
            include_directories(${PCAP_INCLUDE_DIRS})
            set(PACKET_LIB ${PCAP_LIBRARIES})
        endif()
    endif()
endif()

include_directories("third_party")

add_executable(phantom
    src/main.cpp
    src/types.cpp
    src/logger.cpp
    src/network.cpp
    src/arp_spoof.cpp
    src/dns_spoof.cpp
    src/cert_manager.cpp
    src/proxy.cpp
    src/dpi_engine.cpp
    src/app_parsers.cpp
    src/device_tracker.cpp
    src/wifi_tools.cpp
    src/json_utils.cpp
)

target_link_libraries(phantom
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${PACKET_LIB}
)

if(WIN32)
    target_compile_definitions(phantom PRIVATE _WINSOCK_DEPRECATED_NO_WARNINGS WIN32_LEAN_AND_MEAN)
endif()
