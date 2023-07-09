
#include <iostream>

#include "target.h"
#include "httpssession.h"

int main() {
    auto loop = uvw::Loop::getDefault();
    auto tcp_handle = loop->resource<uvw::TCPHandle>();

    auto family = AF_INET;
    std::vector<Target> target_list;
    std::vector<std::string> raw_target_list;
    raw_target_list.emplace_back("https://google.com");
    auto request = loop->resource<uvw::GetAddrInfoReq>();
    for (uint i = 0; i < raw_target_list.size(); i++) {
        uvw::Addr addr;
        struct http_parser_url parsed = {};
        std::string url = raw_target_list[i];
        if(url.rfind("https://", 0) != 0) {
            url.insert(0, "https://");
        }
        int ret = http_parser_parse_url(url.c_str(), strlen(url.c_str()), 0, &parsed);
        if(ret != 0) {
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
            std::cerr << "name did not resolve to valid IP address for this inet family: " << raw_target_list[i] << std::endl;
            return 1;
        }

        if (family == AF_INET) {
            addr = uvw::details::address<uvw::IPv4>((struct sockaddr_in *)node->ai_addr);
        } else if (family == AF_INET6) {
            addr = uvw::details::address<uvw::IPv6>((struct sockaddr_in6 *)node->ai_addr);
        }
        target_list.push_back({&parsed, addr.ip, url});
    }

    auto client = std::make_shared<HTTPSSession>(tcp_handle,
                                                 nullptr,
                                                 nullptr,
                                                 nullptr,
                                                 nullptr,
                                                 target_list[0],
                                                 HTTPMethod::GET);


    loop->run();
    loop = nullptr;

    std::cout << "Hello, World!" << std::endl;

    return 0;
}
