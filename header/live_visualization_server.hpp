#pragma once
// =============================================================================
// live_visualization_server.hpp  —  Minimal HTTP server for live visualization
//
// This header declares a tiny single-threaded HTTP server used in the demo to
// serve an HTML visualization and a `/api/state` endpoint which returns JSON.
// Platform-specific socket includes are moved into the .cpp implementation
// to avoid requiring Winsock headers at compilation sites that don't use the
// networking code.
// =============================================================================
#include <string>
#include <thread>
#include <functional>
#include <atomic>

using Socket = int; // actual type resolved in source file; kept opaque here
static const Socket invalid_socket = -1;

class LiveVisualizationServer {
public:
    using StateProvider = std::function<std::string()>;

    LiveVisualizationServer() = default;
    ~LiveVisualizationServer() { stop(); }

    bool start(const std::string& page_html,
               StateProvider state_provider,
               int preferred_port = 8080);
    void stop();
    bool is_running() const { return running_.load(); }
    std::string url() const;

private:
    Socket listen_socket_ = invalid_socket;
    int    port_ = 0;
    std::thread server_thread_;
    std::atomic<bool> running_ = false;
    std::string page_html_;
    StateProvider state_provider_ = nullptr;

    static bool init_sockets();
    static void close_socket(Socket s);
    static std::string http_response(const std::string& status,
                                     const std::string& content_type,
                                     const std::string& body);
    static std::string not_found_body();
    static std::string path_from_request(const std::string& request);
    bool bind_and_listen(int preferred_port);
    void serve_loop();
    void handle_client(Socket client);
};
