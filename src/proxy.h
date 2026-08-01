#pragma once
#include "types.h"
#include "cert_manager.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <map>
#include <queue>
#include <condition_variable>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
#define INVALID_SOCK INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
using socket_t = int;
#define INVALID_SOCK (-1)
#define SOCKET_ERROR (-1)
#define closesocket close
#endif

namespace phantom {

struct ProxyConnection {
    socket_t client_sock;
    socket_t remote_sock;
    std::string client_ip;
    uint16_t client_port;
    std::string target_host;
    uint16_t target_port;
    bool is_https;
    HttpTransaction http_txn;
    std::vector<uint8_t> client_buffer;
    std::vector<uint8_t> remote_buffer;
    bool handshake_done;
    std::chrono::system_clock::time_point created;
};

class MitmProxy {
public:
    MitmProxy();
    ~MitmProxy();

    void SetPort(uint16_t port);
    void SetDpiCallback(std::function<void(HttpTransaction&, const std::string& client_ip)> cb);
    void SetCredentialCallback(std::function<void(const CapturedCredential&)> cb);

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

    uint64_t GetConnectionsHandled() const { return connections_handled_; }
    uint64_t GetBytesProxied() const { return bytes_proxied_; }

private:
    void AcceptLoop();
    void HandleConnection(std::shared_ptr<ProxyConnection> conn);
    bool DoTlsHandshakeWithClient(std::shared_ptr<ProxyConnection> conn);
    bool ConnectToRemote(std::shared_ptr<ProxyConnection> conn);
    bool DoTlsHandshakeWithRemote(std::shared_ptr<ProxyConnection> conn);
    bool ParseHttpRequest(std::shared_ptr<ProxyConnection> conn);
    void RelayData(socket_t src, socket_t dst, std::vector<uint8_t>& buffer,
                   std::shared_ptr<ProxyConnection> conn, bool from_client);
    void ProcessHttpResponse(std::shared_ptr<ProxyConnection> conn);
    void SendHttpError(std::shared_ptr<ProxyConnection> conn, int code,
                       const std::string& msg);

    static bool SetNonBlocking(socket_t sock);
    static bool SetSocketOptions(socket_t sock);
    static void CloseSocket(socket_t& sock);

    uint16_t port_ = 8080;
    socket_t listen_sock_ = INVALID_SOCK;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    std::atomic<uint64_t> connections_handled_{0};
    std::atomic<uint64_t> bytes_proxied_{0};

    std::function<void(HttpTransaction&, const std::string&)> dpi_callback_;
    std::function<void(const CapturedCredential&)> cred_callback_;

#ifdef _WIN32
    static bool wsa_initialized_;
    static void InitWsa();
#endif
};

} // namespace phantom
