#include "xssl_ctx.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

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
#define PORT 20030
using namespace std::chrono_literals;

static void ReadCB(struct bufferevent *bev, void *arg)
{
    char buf[1024] = { 0 };
    int  len       = bufferevent_read(bev, buf, sizeof(buf) - 1);
    if (len > 0)
        std::cout << buf << std::endl;
    std::string data = "buffervent client send";
    bufferevent_write(bev, data.c_str(), data.size());
}

static void WriteCB(struct bufferevent *bev, void *arg)
{
}

static void EventCB(struct bufferevent *bev, short what, void *arg)
{
    ///SSL握手成功 （客户端和服务端都会进入，协商秘钥成功）
    if (what & BEV_EVENT_CONNECTED)
    {
        std::string data = "buffervent client send";
        bufferevent_write(bev, data.c_str(), data.size());
    }
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    WSAData wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    if (argc > 1)
    {
        if (strcmp(argv[1], "client") == 0)
        {
            printf("Client start.\n");

            XSSL_CTX client_ctx;
            client_ctx.initClient();

            /// 客户端
            std::string           ip   = "127.0.0.1";
            event_base           *base = event_base_new();
            int                   sock = socket(AF_INET, SOCK_STREAM, 0);
            std::shared_ptr<XSSL> xssl = client_ctx.createXSSL(sock);
            struct bufferevent   *bev  = bufferevent_openssl_socket_new(base, sock, xssl->get_ssl(),
                                                                        BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
            if (bev == nullptr)
            {
                std::cout << "bufferevent_openssl_socket_new failed!" << std::endl;
                xssl->close();
                client_ctx.close();
                getchar();
                return -1;
            }


            sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_addr.s_addr = inet_addr(ip.c_str());
            sa.sin_port        = htons(PORT);
            bufferevent_setcb(bev, ReadCB, WriteCB, EventCB, xssl.get());
            bufferevent_enable(bev, EV_READ | EV_WRITE);
            bufferevent_socket_connect(bev, reinterpret_cast<sockaddr *>(&sa), sizeof(sa));
            std::cout << "connect " << ip << ":" << PORT << " success!" << std::endl;
            for (;;)
            {
                event_base_loop(base, EVLOOP_NONBLOCK);
                std::this_thread::sleep_for(1ms);
            }
            xssl->close();
            client_ctx.close();
            event_base_free(base);
        }
    }
    else
    {
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
                ss << data;
                ss << i;
                char buf[1024] = { 0 };
                int  len       = 0;
                len            = xssl->read(buf, sizeof(buf) - 1);
                if (len > 0)
                    std::cout << buf << std::endl;

                len = xssl->write(ss.str().c_str(), ss.str().size());
                if (len <= 0)
                    break;
                std::this_thread::sleep_for(500ms);
            }
            xssl->close();
        }
        ctx.close();
    }


#ifdef _WIN32
    WSACleanup();
#endif
    getchar();
    return 0;
}
