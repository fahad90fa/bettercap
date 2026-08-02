#include "proxy.h"
#include "logger.h"
#include "config.h"
#include "dpi_engine.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
bool MitmProxy::wsa_initialized_ = false;
void MitmProxy::InitWsa() {
    if (!wsa_initialized_) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_initialized_ = true;
    }
}
#endif

namespace phantom {

MitmProxy::MitmProxy() {
#ifdef _WIN32
    InitWsa();
#endif
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

MitmProxy::~MitmProxy() { Stop(); }

void MitmProxy::SetPort(uint16_t port) { port_ = port; }
void MitmProxy::SetDpiCallback(std::function<void(HttpTransaction&, const std::string&)> cb) {
    dpi_callback_ = std::move(cb);
}
void MitmProxy::SetCredentialCallback(std::function<void(const CapturedCredential&)> cb) {
    cred_callback_ = std::move(cb);
}

bool MitmProxy::SetNonBlocking(socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    return fcntl(sock, F_SETFL, O_NONBLOCK) == 0;
#endif
}

bool MitmProxy::SetSocketOptions(socket_t sock) {
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&one, sizeof(one));
#endif
    int buf_size = 262144;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&buf_size, sizeof(buf_size));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&buf_size, sizeof(buf_size));
    return true;
}

void MitmProxy::CloseSocket(socket_t& sock) {
    if (sock != INVALID_SOCK) {
        closesocket(sock);
        sock = INVALID_SOCK;
    }
}

void MitmProxy::SendHttpError(std::shared_ptr<ProxyConnection> conn, int code, const std::string& msg) {
    std::string response = "HTTP/1.1 " + std::to_string(code) + " " + msg + "\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
    send(conn->client_sock, response.c_str(), (int)response.size(), 0);
}

bool MitmProxy::ParseHttpRequest(std::shared_ptr<ProxyConnection> conn) {
    std::string request(conn->client_buffer.begin(), conn->client_buffer.end());
    size_t header_end = request.find("\r\n\r\n");
    if (header_end == std::string::npos) return false;

    std::string header_section = request.substr(0, header_end);
    std::string body = request.substr(header_end + 4);

    size_t first_space = request.find(' ');
    if (first_space == std::string::npos) return false;
    size_t second_space = request.find(' ', first_space + 1);
    if (second_space == std::string::npos) return false;

    conn->http_txn.method = request.substr(0, first_space);
    std::string full_url = request.substr(first_space + 1, second_space - first_space - 1);

    conn->http_txn.user_agent = "";
    conn->http_txn.referer = "";
    conn->http_txn.cookie = "";
    conn->http_txn.auth_header = "";
    conn->http_txn.request_content_type = "";
    conn->http_txn.request_body = "";

    std::istringstream header_stream(header_section);
    std::string line;
    bool first_line = true;
    while (std::getline(header_stream, line)) {
        if (first_line) { first_line = false; continue; }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        size_t colon = line.find(": ");
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        std::string value = line.substr(colon + 2);

        std::string lkey = key;
        std::transform(lkey.begin(), lkey.end(), lkey.begin(), ::tolower);

        if (lkey == "host") conn->http_txn.host = value;
        else if (lkey == "user-agent") conn->http_txn.user_agent = value;
        else if (lkey == "referer") conn->http_txn.referer = value;
        else if (lkey == "cookie") conn->http_txn.cookie = value;
        else if (lkey == "authorization") conn->http_txn.auth_header = value;
        else if (lkey == "content-type") conn->http_txn.request_content_type = value;
        else if (lkey == "x-instagram-ajax" || lkey == "x-csrf-token" ||
                 lkey == "x-auth-token" || lkey == "x-access-token") {
            conn->http_txn.auth_header = value;
        }
        conn->http_txn.request_headers[key] = value;
    }

    conn->is_https = (conn->http_txn.method == "CONNECT");
    conn->http_txn.is_https = conn->is_https;

    if (conn->is_https) {
        size_t colon_pos = full_url.find(':');
        conn->http_txn.host = (colon_pos != std::string::npos)
            ? full_url.substr(0, colon_pos)
            : full_url;
        conn->target_host = conn->http_txn.host;
        conn->target_port = (colon_pos != std::string::npos)
            ? (uint16_t)std::stoi(full_url.substr(colon_pos + 1))
            : 443;
        conn->http_txn.path = "";
        conn->http_txn.full_url = "https://" + full_url;
    } else {
        if (full_url.find("http://") == 0 || full_url.find("https://") == 0) {
            size_t scheme_end = full_url.find("://");
            std::string after_scheme = full_url.substr(scheme_end + 3);
            size_t slash = after_scheme.find('/');
            if (slash != std::string::npos) {
                conn->http_txn.host = after_scheme.substr(0, slash);
                conn->http_txn.path = after_scheme.substr(slash);
            } else {
                conn->http_txn.host = after_scheme;
                conn->http_txn.path = "/";
            }
        } else {
            conn->http_txn.path = full_url;
        }
        conn->target_host = conn->http_txn.host;
        conn->target_port = 80;
        conn->http_txn.full_url = "http://" + conn->http_txn.host + conn->http_txn.path;
    }

    if (conn->http_txn.method == "POST" && !body.empty()) {
        conn->http_txn.request_body = body.substr(0, MAX_BODY_PARSE_SIZE);
    }

    conn->http_txn.client_ip = conn->client_ip;
    conn->http_txn.start_time = std::chrono::system_clock::now();
    return true;
}

bool MitmProxy::ConnectToRemote(std::shared_ptr<ProxyConnection> conn) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(conn->target_port);
    int err = getaddrinfo(conn->target_host.c_str(), port_str.c_str(), &hints, &result);
    if (err != 0 || !result) {
        LOG_ERROR("Cannot resolve " + conn->target_host + ": " + gai_strerror(err));
        return false;
    }

    conn->remote_sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (conn->remote_sock == INVALID_SOCK) {
        freeaddrinfo(result);
        return false;
    }

    SetSocketOptions(conn->remote_sock);
    SetNonBlocking(conn->remote_sock);

    int ret = connect(conn->remote_sock, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    if (ret == SOCKET_ERROR) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
#else
        if (errno != EINPROGRESS) {
#endif
            CloseSocket(conn->remote_sock);
            return false;
        }
    }

    struct pollfd pfd;
    pfd.fd = conn->remote_sock;
    pfd.events = POLLOUT;
    int poll_result = poll(&pfd, 1, PROXY_RECV_TIMEOUT * 1000);

    if (poll_result <= 0) {
        CloseSocket(conn->remote_sock);
        return false;
    }

    int sock_err = 0;
    socklen_t err_len = sizeof(sock_err);
    getsockopt(conn->remote_sock, SOL_SOCKET, SO_ERROR, (char*)&sock_err, &err_len);
    if (sock_err != 0) {
        CloseSocket(conn->remote_sock);
        return false;
    }

    return true;
}

bool MitmProxy::DoTlsHandshakeWithClient(std::shared_ptr<ProxyConnection> conn) {
    const LeafCert& leaf = CertManager::Instance().GetCertForDomain(conn->target_host);
    if (leaf.cert_pem.empty()) {
        LOG_ERROR("No leaf cert for " + conn->target_host);
        return false;
    }

    BIO* cert_bio = BIO_new_mem_buf(leaf.cert_pem.c_str(), (int)leaf.cert_pem.size());
    X509* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);

    BIO* key_bio = BIO_new_mem_buf(leaf.key_pem.c_str(), (int)leaf.key_pem.size());
    EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);

    if (!cert || !key) {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
        LOG_ERROR("Failed to parse leaf cert/key for " + conn->target_host);
        return false;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, key);
    SSL_CTX_check_private_key(ctx);

    if (!CertManager::Instance().GetCaCertPem().empty()) {
        BIO* ca_bio = BIO_new_mem_buf(CertManager::Instance().GetCaCertPem().c_str(),
            (int)CertManager::Instance().GetCaCertPem().size());
        X509* ca_cert = PEM_read_bio_X509(ca_bio, nullptr, nullptr, nullptr);
        BIO_free(ca_bio);
        if (ca_cert) {
            SSL_CTX_add_extra_chain_cert(ctx, ca_cert);
        }
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4");

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)conn->client_sock);
    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        LOG_DEBUG("TLS handshake with client failed for " + conn->target_host +
                  " (SSL error " + std::to_string(err) + ")");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(key);
        return false;
    }

    conn->handshake_done = true;
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    X509_free(cert);
    EVP_PKEY_free(key);
    return true;
}

bool MitmProxy::DoTlsHandshakeWithRemote(std::shared_ptr<ProxyConnection> conn) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)conn->remote_sock);
    SSL_set_tlsext_host_name(ssl, conn->target_host.c_str());

    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        LOG_DEBUG("TLS handshake with remote failed for " + conn->target_host +
                  " (SSL error " + std::to_string(err) + ")");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return true;
}

void MitmProxy::ProcessHttpResponse(std::shared_ptr<ProxyConnection> conn) {
    if (!dpi_callback_) return;
    if (conn->http_txn.response_body.empty()) return;
    dpi_callback_(conn->http_txn, conn->client_ip);
}

void MitmProxy::HandleConnection(std::shared_ptr<ProxyConnection> conn) {
    connections_handled_++;
    if (!ParseHttpRequest(conn)) {
        SendHttpError(conn, 400, "Bad Request");
        return;
    }

    LOG_DEBUG("[" + conn->client_ip + "] " + conn->http_txn.method + " " + conn->http_txn.full_url);

    if (conn->is_https) {
        std::string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(conn->client_sock, response.c_str(), (int)response.size(), 0);

        if (!ConnectToRemote(conn)) {
            SendHttpError(conn, 502, "Bad Gateway");
            return;
        }

        if (!DoTlsHandshakeWithClient(conn) || !DoTlsHandshakeWithRemote(conn)) {
            SendHttpError(conn, 502, "Bad Gateway");
            return;
        }

        SSL_CTX* client_ctx = SSL_CTX_new(TLS_server_method());
        const LeafCert& leaf = CertManager::Instance().GetCertForDomain(conn->target_host);
        BIO* cb = BIO_new_mem_buf(leaf.cert_pem.c_str(), (int)leaf.cert_pem.size());
        X509* lcert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
        BIO_free(cb);
        BIO* kb = BIO_new_mem_buf(leaf.key_pem.c_str(), (int)leaf.key_pem.size());
        EVP_PKEY* lkey = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
        BIO_free(kb);

        if (lcert && lkey) {
            SSL_CTX_use_certificate(client_ctx, lcert);
            SSL_CTX_use_PrivateKey(client_ctx, lkey);
            SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
            SSL_CTX_set_cipher_list(client_ctx,
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-CHACHA20-POLY1305:AES256-GCM-SHA384:HIGH:!aNULL:!MD5");
        }

        SSL* client_ssl = SSL_new(client_ctx);
        SSL_set_fd(client_ssl, (int)conn->client_sock);
        SSL_accept(client_ssl);

        SSL_CTX* remote_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(remote_ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_min_proto_version(remote_ctx, TLS1_2_VERSION);
        SSL* remote_ssl = SSL_new(remote_ctx);
        SSL_set_fd(remote_ssl, (int)conn->remote_sock);
        SSL_set_tlsext_host_name(remote_ssl, conn->target_host.c_str());
        SSL_connect(remote_ssl);

        uint8_t buffer[BUFFER_SIZE];
        struct pollfd pfds[2];
        pfds[0].fd = conn->client_sock;
        pfds[0].events = POLLIN;
        pfds[1].fd = conn->remote_sock;
        pfds[1].events = POLLIN;

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(PROXY_RECV_TIMEOUT);

        while (conn->client_sock != INVALID_SOCK && conn->remote_sock != INVALID_SOCK) {
            int remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining_ms <= 0) break;

            int ret = poll(pfds, 2, remaining_ms);
            if (ret <= 0) break;

            if (pfds[0].revents & POLLIN) {
                int n = SSL_read(client_ssl, buffer, sizeof(buffer));
                if (n <= 0) break;
                bytes_proxied_ += n;
                SSL_write(remote_ssl, buffer, n);
            }

            if (pfds[1].revents & POLLIN) {
                int n = SSL_read(remote_ssl, buffer, sizeof(buffer));
                if (n <= 0) break;
                bytes_proxied_ += n;
                std::string resp((char*)buffer, n);
                size_t rhdr = resp.find("\r\n\r\n");
                if (rhdr != std::string::npos) {
                    size_t sp = resp.find(' ');
                    if (sp != std::string::npos) {
                        conn->http_txn.response_code = std::atoi(resp.c_str() + sp + 1);
                    }
                    std::string rheaders = resp.substr(0, rhdr);
                    std::istringstream rhs(rheaders);
                    std::string rl;
                    bool rf = true;
                    while (std::getline(rhs, rl)) {
                        if (rf) { rf = false; continue; }
                        if (!rl.empty() && rl.back() == '\r') rl.pop_back();
                        size_t c = rl.find(": ");
                        if (c == std::string::npos) continue;
                        std::string lk = rl.substr(0, c);
                        std::transform(lk.begin(), lk.end(), lk.begin(), ::tolower);
                        std::string lv = rl.substr(c + 2);
                        conn->http_txn.response_headers[rl.substr(0, c)] = lv;
                        if (lk == "content-type") conn->http_txn.response_content_type = lv;
                    }
                    if (rhdr + 4 < (size_t)n) {
                        conn->http_txn.response_body = resp.substr(rhdr + 4,
                            std::min((size_t)MAX_BODY_PARSE_SIZE, (size_t)n - rhdr - 4));
                        ProcessHttpResponse(conn);
                    }
                }
                SSL_write(client_ssl, buffer, n);
            }
        }

        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        SSL_CTX_free(client_ctx);
        SSL_shutdown(remote_ssl);
        SSL_free(remote_ssl);
        SSL_CTX_free(remote_ctx);
        if (lcert) X509_free(lcert);
        if (lkey) EVP_PKEY_free(lkey);
    } else {
        if (!ConnectToRemote(conn)) {
            SendHttpError(conn, 502, "Bad Gateway");
            return;
        }

        std::string request(conn->client_buffer.begin(), conn->client_buffer.end());
        if (request.find("http://" + conn->target_host) == 0) {
            size_t after_host = request.find(conn->target_host) + conn->target_host.size();
            request = conn->http_txn.method + " " + conn->http_txn.path +
                      request.substr(request.find("\r\n"));
        }
        send(conn->remote_sock, request.c_str(), (int)request.size(), 0);

        uint8_t buffer[BUFFER_SIZE];
        struct pollfd pfds[2];
        pfds[0].fd = conn->client_sock;
        pfds[0].events = POLLIN;
        pfds[1].fd = conn->remote_sock;
        pfds[1].events = POLLIN;

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(PROXY_RECV_TIMEOUT);
        bool got_response_header = false;

        while (conn->client_sock != INVALID_SOCK && conn->remote_sock != INVALID_SOCK) {
            int remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining_ms <= 0) break;

            int ret = poll(pfds, 2, remaining_ms);
            if (ret <= 0) break;

            if (pfds[1].revents & POLLIN) {
                int n = recv(conn->remote_sock, (char*)buffer, sizeof(buffer), 0);
                if (n <= 0) break;
                bytes_proxied_ += n;
                if (!got_response_header) {
                    std::string resp((char*)buffer, n);
                    size_t rhdr = resp.find("\r\n\r\n");
                    if (rhdr != std::string::npos) {
                        got_response_header = true;
                        size_t sp = resp.find(' ');
                        if (sp != std::string::npos) conn->http_txn.response_code = std::atoi(resp.c_str() + sp + 1);

                        std::string rheaders = resp.substr(0, rhdr);
                        std::istringstream rhs(rheaders);
                        std::string rl;
                        bool rf = true;
                        while (std::getline(rhs, rl)) {
                            if (rf) { rf = false; continue; }
                            if (!rl.empty() && rl.back() == '\r') rl.pop_back();
                            size_t c = rl.find(": ");
                            if (c == std::string::npos) continue;
                            conn->http_txn.response_headers[rl.substr(0, c)] = rl.substr(c + 2);
                            std::string lk = rl.substr(0, c);
                            std::transform(lk.begin(), lk.end(), lk.begin(), ::tolower);
                            if (lk == "content-type") conn->http_txn.response_content_type = rl.substr(c + 2);
                        }
                        if (rhdr + 4 < (size_t)n) {
                            conn->http_txn.response_body = resp.substr(rhdr + 4,
                                std::min((size_t)MAX_BODY_PARSE_SIZE, (size_t)n - rhdr - 4));
                            ProcessHttpResponse(conn);
                        }
                    }
                }
                send(conn->client_sock, (char*)buffer, n, 0);
            }

            if (pfds[0].revents & POLLIN) {
                int n = recv(conn->client_sock, (char*)buffer, sizeof(buffer), 0);
                if (n <= 0) break;
                bytes_proxied_ += n;
                send(conn->remote_sock, (char*)buffer, n, 0);
            }
        }
    }

    CloseSocket(conn->client_sock);
    CloseSocket(conn->remote_sock);
}

void MitmProxy::AcceptLoop() {
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    while (running_) {
        // listen_sock_ is non-blocking, so gate accept() behind a timed
        // select() instead of spinning: without this, an idle listener
        // makes accept() return EWOULDBLOCK continuously, pegging this
        // thread at 100% CPU and flooding the log with "Accept error".
        fd_set accept_set;
        FD_ZERO(&accept_set);
        FD_SET(listen_sock_, &accept_set);
        struct timeval accept_tv{0, 200000}; // 200ms
        int ready = select((int)listen_sock_ + 1, &accept_set, nullptr, nullptr, &accept_tv);
        if (ready <= 0) continue;

        socket_t client = accept(listen_sock_, (struct sockaddr*)&client_addr, &client_len);
        if (client == INVALID_SOCK) {
            continue; // spurious wakeup, nothing to log
        }

        SetNonBlocking(client);
        SetSocketOptions(client);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));

        auto conn = std::make_shared<ProxyConnection>();
        conn->client_sock = client;
        conn->remote_sock = INVALID_SOCK;
        conn->client_ip = ip_str;
        conn->client_port = ntohs(client_addr.sin_port);
        conn->handshake_done = false;
        conn->created = std::chrono::system_clock::now();

        uint8_t buffer[BUFFER_SIZE];
        fd_set read_set;
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        FD_ZERO(&read_set);
        FD_SET(client, &read_set);
        int sel = select((int)client + 1, &read_set, nullptr, nullptr, &tv);

        if (sel > 0) {
            int n = recv(client, (char*)buffer, sizeof(buffer), 0);
            if (n > 0) {
                conn->client_buffer.assign(buffer, buffer + n);
                std::thread([this, conn]() { HandleConnection(conn); }).detach();
                continue;
            }
        }

        CloseSocket(client);
    }
}

bool MitmProxy::Start() {
    if (running_) return true;

    if (!CertManager::Instance().Initialize()) {
        LOG_ERROR("Cannot start proxy — certificate manager failed");
        return false;
    }

    listen_sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock_ == INVALID_SOCK) {
        LOG_ERROR("Cannot create proxy socket");
        return false;
    }

    SetSocketOptions(listen_sock_);
    SetNonBlocking(listen_sock_);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(listen_sock_, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        LOG_ERROR("Cannot bind proxy to port " + std::to_string(port_));
        CloseSocket(listen_sock_);
        return false;
    }

    if (listen(listen_sock_, MAX_PROXY_CONNECTIONS) != 0) {
        LOG_ERROR("Cannot listen on proxy socket");
        CloseSocket(listen_sock_);
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&MitmProxy::AcceptLoop, this);
    LOG_SUCCESS("MITM proxy listening on port " + std::to_string(port_));
    return true;
}

void MitmProxy::Stop() {
    if (!running_) return;
    running_ = false;
    CloseSocket(listen_sock_);
    if (accept_thread_.joinable()) accept_thread_.join();
    LOG_INFO("MITM proxy stopped | Connections: " +
             std::to_string(connections_handled_.load()) +
             " | Bytes: " + std::to_string(bytes_proxied_.load()));
}

} // namespace phantom
