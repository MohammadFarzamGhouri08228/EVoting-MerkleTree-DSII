#pragma once

#include <atomic>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

class LiveVisualizationServer {
public:
    using StateProvider = std::function<std::string()>;

private:
#ifdef _WIN32
    using Socket = SOCKET;
    static constexpr Socket invalid_socket = INVALID_SOCKET;
#else
    using Socket = int;
    static constexpr Socket invalid_socket = -1;
#endif

    Socket              listen_socket_ = invalid_socket;
    std::thread         server_thread_;
    std::atomic<bool>   running_{false};
    int                 port_ = 0;
    std::string         page_html_;
    StateProvider       state_provider_;

    static void close_socket(Socket s) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }

    static bool init_sockets() {
#ifdef _WIN32
        static bool initialized = false;
        static WSADATA data;
        if (!initialized) {
            if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
                return false;
            initialized = true;
        }
#endif
        return true;
    }

    static std::string http_response(
        const std::string& status,
        const std::string& content_type,
        const std::string& body)
    {
        std::ostringstream out;
        out << "HTTP/1.1 " << status << "\r\n";
        out << "Content-Type: " << content_type << "; charset=utf-8\r\n";
        out << "Content-Length: " << body.size() << "\r\n";
        out << "Cache-Control: no-store\r\n";
        out << "Connection: close\r\n\r\n";
        out << body;
        return out.str();
    }

    static std::string not_found_body() {
        return "<!doctype html><html><body><h1>404</h1><p>Not found.</p></body></html>";
    }

    static std::string path_from_request(const std::string& request) {
        const std::string prefix = "GET ";
        const std::size_t start = request.find(prefix);
        if (start == std::string::npos) return "/";
        const std::size_t path_start = start + prefix.size();
        const std::size_t path_end = request.find(' ', path_start);
        if (path_end == std::string::npos) return "/";
        return request.substr(path_start, path_end - path_start);
    }

    bool bind_and_listen(int preferred_port) {
        if (!init_sockets()) return false;

        for (int port = preferred_port; port < preferred_port + 20; ++port) {
            Socket s = ::socket(AF_INET, SOCK_STREAM, 0);
            if (s == invalid_socket) continue;

            int yes = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&yes), sizeof(yes));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(static_cast<unsigned short>(port));

            if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
                ::listen(s, 8) == 0) {
                listen_socket_ = s;
                port_ = port;
                return true;
            }

            close_socket(s);
        }
        return false;
    }

    void handle_client(Socket client) {
        char buffer[4096];
        const int received = recv(client, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            close_socket(client);
            return;
        }
        buffer[received] = '\0';

        const std::string request(buffer);
        const std::string path = path_from_request(request);

        std::string response;
        if (path == "/" || path == "/index.html") {
            response = http_response("200 OK", "text/html", page_html_);
        } else if (path == "/api/state") {
            response = http_response("200 OK", "application/json",
                                     state_provider_ ? state_provider_() : "{}");
        } else {
            response = http_response("404 Not Found", "text/html", not_found_body());
        }

        send(client, response.c_str(), static_cast<int>(response.size()), 0);
        close_socket(client);
    }

    void serve_loop() {
        while (running_) {
            sockaddr_in client_addr{};
#ifdef _WIN32
            int len = sizeof(client_addr);
#else
            socklen_t len = sizeof(client_addr);
#endif
            Socket client = accept(listen_socket_, reinterpret_cast<sockaddr*>(&client_addr), &len);
            if (client == invalid_socket) {
                if (!running_) break;
                continue;
            }
            handle_client(client);
        }
    }

public:
    LiveVisualizationServer() = default;
    ~LiveVisualizationServer() { stop(); }

    LiveVisualizationServer(const LiveVisualizationServer&) = delete;
    LiveVisualizationServer& operator=(const LiveVisualizationServer&) = delete;

    bool start(const std::string& page_html,
               StateProvider state_provider,
               int preferred_port = 8080)
    {
        if (running_) return true;
        page_html_ = page_html;
        state_provider_ = std::move(state_provider);

        if (!bind_and_listen(preferred_port))
            return false;

        running_ = true;
        server_thread_ = std::thread([this]() { serve_loop(); });
        return true;
    }

    void stop() {
        if (!running_) return;
        running_ = false;

        if (listen_socket_ != invalid_socket) {
            Socket wake = ::socket(AF_INET, SOCK_STREAM, 0);
            if (wake != invalid_socket) {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port = htons(static_cast<unsigned short>(port_));
                ::connect(wake, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
                close_socket(wake);
            }

#ifdef _WIN32
            shutdown(listen_socket_, SD_BOTH);
#else
            shutdown(listen_socket_, SHUT_RDWR);
#endif
            close_socket(listen_socket_);
            listen_socket_ = invalid_socket;
        }

        if (server_thread_.joinable())
            server_thread_.join();
    }

    bool is_running() const { return running_; }
    int  port() const { return port_; }

    std::string url() const {
        return "http://127.0.0.1:" + std::to_string(port_) + "/";
    }
};
