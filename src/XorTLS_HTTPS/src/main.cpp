#include "xssl_ctx.h"

#ifdef _WIN32
#include <winsock2.h>
#define socklen_t int
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <sstream>
#include <thread>

using namespace std::chrono_literals;


#define PORT 443 /// HTTPS PORT

int main(int argc, char *argv[])
{
#ifdef _WIN32
    WSAData wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif


    printf("Server start.\n");

    XSSL_CTX ctx;
    if (!ctx.initServer("assert/server.crt", "assert/server.key"))
    {
        std::cout << R"(ctx.initServer("assert/server.crt", "assert/server.key") failed！)" << std::endl;
        getchar();
        return -1;
    }
    std::cout << R"(ctx.initServer("assert/server.crt", "assert/server.key") success！)" << std::endl;

    int         accept_sock = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa_server;
    memset(&sa_server, 0, sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons(PORT);

    int re = ::bind(accept_sock, reinterpret_cast<sockaddr *>(&sa_server), sizeof(sa_server));
    if (re != 0)
    {
        std::cerr << " bind port:" << PORT << " failed!" << std::endl;
        getchar();
    }

    ::listen(accept_sock, 10);
    std::cout << "start listen port " << PORT << std::endl;

    for (;;)
    {
        int client_socket = ::accept(accept_sock, nullptr, nullptr);
        if (client_socket <= 0)
            break;
        std::cout << "accept socket" << std::endl;
        auto xssl = ctx.createXSSL(client_socket);
        if (xssl->isEmpty())
        {
            std::cout << "xssl.isEmpty" << std::endl;
            continue;
        }
        if (!xssl->accept())
        {
            xssl->close();
            continue;
        }

        std::string data = "Server Write";
        for (int i = 0;; i++)
        {
            std::stringstream ss;
            char              buf[1024] = { 0 };
            int               len       = 0;
            len                         = xssl->read(buf, sizeof(buf) - 1);
            if (len > 0)
            {
                /// accept socket
                /// SSL_accept success!
                /// GET / HTTP/1.1
                /// Host: 127.0.0.1
                /// Connection: keep-alive
                /// Cache-Control: max-age=0
                /// sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"
                /// sec-ch-ua-mobile: ?0
                /// sec-ch-ua-platform: "Windows" / "Macos"
                /// Upgrade-Insecure-Requests: 1
                /// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
                /// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
                /// Sec-Fetch-Site: cross-site
                /// Sec-Fetch-Mode: navigate
                /// Sec-Fetch-User: ?1
                /// Sec-Fetch-Dest: document
                /// Accept-Encoding: gzip, deflate, br, zstd
                /// Accept-Language: zh-CN,zh;q=0.9

                std::cout << buf << std::endl;
            }


            /// 解析GET 得到访问的资源

            /// HTTP 响应 状态行、消息报头、响应正文
            const std::string &html = "<h1>Test Https(openssl3.0)</h1>"; /// 响应正文
            ss << "HTTP/1.1 200 OK\r\n";
            ss << "Content-Type: text/html\r\n";
            ss << "Content-Length: " << html.size() << "\r\n";
            ss << "Connection: keep-alive\r\n";
            ss << "Server: XorTLS_HTTPS\r\n";
            ss << "\r\n";
            ss << html;

            len = xssl->write(ss.str().c_str(), ss.str().size());
            if (len <= 0)
                break;
            std::this_thread::sleep_for(1ms);
        }
        xssl->close();
    }
    ctx.close();


#ifdef _WIN32
    WSACleanup();
#endif
    getchar();
    return 0;
}
