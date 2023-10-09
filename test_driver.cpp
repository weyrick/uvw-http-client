
#include <iostream>

#include "target.h"
#include "httpssession.h"

void connect_tcp_events(std::shared_ptr<uvw::TCPHandle> tcp_handle, std::shared_ptr<TCPSession> tcp_session) {
    /** SOCKET CALLBACKS **/

    // SOCKET: local socket was closed, cleanup resources and possibly restart another connection
    tcp_handle->on<uvw::CloseEvent>([&tcp_handle, &tcp_session](uvw::CloseEvent &event, uvw::TCPHandle &h) {
        if (tcp_handle.get()) {
            tcp_handle->stop();
        }
        tcp_session.reset();
//        tcp_handle.reset();
    });

    // SOCKET: socket error
    tcp_handle->on<uvw::ErrorEvent>([&tcp_handle, &tcp_session](uvw::ErrorEvent &event, uvw::TCPHandle &h) {
        std::cerr <<
                  tcp_handle->sock().ip << ":" << tcp_handle->sock().port <<
                  " - " << event.what() << std::endl;
        // triggers an immediate connection retry.
        tcp_handle->close();
    });

    // INCOMING: remote peer closed connection, EOF
    tcp_handle->on<uvw::EndEvent>([&tcp_session](uvw::EndEvent &event, uvw::TCPHandle &h) {
        tcp_session->on_end_event();
    });

    // OUTGOING: we've finished writing all our data and are shutting down
    tcp_handle->on<uvw::ShutdownEvent>([&tcp_session](uvw::ShutdownEvent &event, uvw::TCPHandle &h) {
        tcp_session->on_shutdown_event();
    });

    // INCOMING: remote peer sends data, pass to session
    tcp_handle->on<uvw::DataEvent>([&tcp_session](uvw::DataEvent &event, uvw::TCPHandle &h) {
        tcp_session->receive_data(event.data.get(), event.length);
    });

    // OUTGOING: write operation has finished
    tcp_handle->on<uvw::WriteEvent>([](uvw::WriteEvent &event, uvw::TCPHandle &h) {
    });

    // SOCKET: on connect
    tcp_handle->on<uvw::ConnectEvent>([&tcp_handle, &tcp_session](uvw::ConnectEvent &event, uvw::TCPHandle &h) {
        tcp_session->on_connect_event();

        // start reading from incoming stream, fires DataEvent when receiving
        tcp_handle->read();
    });
}

int main() {
    auto loop = uvw::Loop::getDefault();

    auto family = AF_INET;

    std::vector<Target> target_list;
    std::vector<std::string> raw_target_list;
    raw_target_list.emplace_back("https://google.com");
    auto request = loop->resource<uvw::GetAddrInfoReq>();
    for (uint i = 0; i < raw_target_list.size(); i++) {
        uvw::Addr addr;
        struct http_parser_url parsed = {};
        std::string url = raw_target_list[i];
        if (url.rfind("https://", 0) != 0) {
            url.insert(0, "https://");
        }
        int ret = http_parser_parse_url(url.c_str(), strlen(url.c_str()), 0, &parsed);
        if (ret != 0) {
            std::cerr << "could not parse url: " << url << std::endl;
            return 1;
        }
        std::string authority(&url[parsed.field_data[UF_HOST].off], parsed.field_data[UF_HOST].len);

        auto target_resolved = request->addrInfoSync(authority, "443");
        if (!target_resolved.first) {
            std::cerr << "unable to resolve target address: " << authority << std::endl;
            if (raw_target_list[i] == "file") {
                std::cerr << "(did you mean to include --targets?)" << std::endl;
            }
            return 1;
        }
        addrinfo *node{target_resolved.second.get()};
        while (node && node->ai_family != family) {
            node = node->ai_next;
        }
        if (!node) {
            std::cerr << "name did not resolve to valid IP address for this inet family: " << raw_target_list[i]
                      << std::endl;
            return 1;
        }

        if (family == AF_INET) {
            addr = uvw::details::address<uvw::IPv4>((struct sockaddr_in *) node->ai_addr);
        } else if (family == AF_INET6) {
            addr = uvw::details::address<uvw::IPv6>((struct sockaddr_in6 *) node->ai_addr);
        }
        target_list.push_back({&parsed, addr.ip, url});
    }

    // ---

    std::shared_ptr<TCPSession> tcp_session;
    auto tcp_handle = loop->resource<uvw::TCPHandle>(family);

    auto malformed_data = [tcp_handle]() {
        tcp_handle->close();
    };
    auto got_dns_message = [](std::unique_ptr<const char[]> data,
                                  size_t size) {
        //process_wire(data.get(), size);
    };
    auto connection_ready = [tcp_session]() {
        /** SEND DATA **/
        //tcp_session->write(std::move(std::get<0>(qt)), std::get<1>(qt));
    };

    tcp_session = std::make_shared<HTTPSSession>(tcp_handle, malformed_data, got_dns_message, connection_ready,
                                                 malformed_data, target_list[0], HTTPMethod::GET);
    connect_tcp_events(tcp_handle, tcp_session);
    auto client = std::make_shared<HTTPSSession>(tcp_handle,
                                                 nullptr,
                                                 nullptr,
                                                 nullptr,
                                                 nullptr,
                                                 target_list[0],
                                                 HTTPMethod::GET);

    // ----
    loop->run();
    loop = nullptr;

    std::cout << "Hello, World!" << std::endl;

    return 0;
}

