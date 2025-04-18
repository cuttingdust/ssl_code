#include "xssl_ctx.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/listener.h>
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

using namespace std::chrono_literals;

enum
{
    PORT = 20030,
};


static void ReadCB(struct bufferevent *bev, void *arg)
{
    char buf[1024] = { 0 };
    int  len       = bufferevent_read(bev, buf, sizeof(buf) - 1);
    if (len > 0)
        std::cout << buf << std::endl;

    std::stringstream ss;
    static int        i;
    i++;
    std::string data = "bufferevent client send ";
    ss << data << i;
    bufferevent_write(bev, ss.str().c_str(), ss.str().size());
}

static void WriteCB(struct bufferevent *bev, void *arg)
{
}

static void SReadCB(struct bufferevent *bev, void *arg)
{
    char buf[1024] = { 0 };
    int  len       = bufferevent_read(bev, buf, sizeof(buf) - 1);
    if (len > 0)
        std::cout << buf << std::endl;

    std::stringstream ss;
    static int        i;
    i++;
    std::string data = "bufferevent server send ";
    ss << data << i;
    bufferevent_write(bev, ss.str().c_str(), ss.str().size());
}

static void EventCB(struct bufferevent *bev, short what, void *arg)
{
    ///SSL握手成功 （客户端和服务端都会进入，协商秘钥成功）
    if (what & BEV_EVENT_CONNECTED)
    {
        XSSL       *ssl  = static_cast<XSSL *>(arg);
        std::string data = "buffervent client send";
        bufferevent_write(bev, data.c_str(), data.size());

        ssl->printCert();
        ssl->printCipher();
    }
}

static void SEventCB(struct bufferevent *bev, short what, void *arg)
{
    /// SSL握手成功 （客户端和服务端都会进入，协商秘钥成功）
    if (what & BEV_EVENT_CONNECTED)
    {
        XSSL *ssl = static_cast<XSSL *>(arg);
        ssl->printCert();
        ssl->printCipher();

        // std::string data = "buffervent client send";
        // bufferevent_write(bev, data.c_str(), data.size());
    }
}

static void ListenCB(struct evconnlistener *e, evutil_socket_t socket, struct sockaddr *a, int socklen, void *arg)
{
    std::cout << __func__ << std::endl;
    XSSL_CTX *ctx      = static_cast<XSSL_CTX *>(arg);
    auto      base     = evconnlistener_get_base(e);
    auto      xssl_tmp = ctx->createXSSL(socket);
    auto      xssl     = new XSSL;
    xssl->set_ssl(xssl_tmp->get_ssl());

    struct bufferevent *bev = bufferevent_openssl_socket_new(base, socket, xssl->get_ssl(), BUFFEREVENT_SSL_ACCEPTING,
                                                             BEV_OPT_CLOSE_ON_FREE);
    if (bev == nullptr)
    {
        std::cout << "bufferevent_openssl_socket_new failed!" << std::endl;
    }

    bufferevent_setcb(bev, SReadCB, WriteCB, SEventCB, xssl);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
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
            std::string                  ip   = "127.0.0.1";
            event_base                  *base = event_base_new();
            int                          sock = socket(AF_INET, SOCK_STREAM, 0);
            static std::shared_ptr<XSSL> xssl = client_ctx.createXSSL(sock);
            struct bufferevent          *bev  = bufferevent_openssl_socket_new(base, sock, xssl->get_ssl(),
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
                std::this_thread::sleep_for(500ms);
            }
            bufferevent_free(bev);
            xssl->close();
            client_ctx.close();
            event_base_free(base);
        }
    }
    else
    {
        printf("Server start.\n");

        XSSL_CTX    ctx;
        event_base *base = event_base_new();

        sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port        = htons(PORT);

        if (!ctx.initServer("assert/server.crt", "assert/server.key"))
        {
            std::cout << R"(ctx.initServer("assert/server.crt", "assert/server.key") failed！)" << std::endl;
            getchar();
            return -1;
        }
        std::cout << R"(ctx.initServer("assert/server.crt", "assert/server.key") success！)" << std::endl;

        evconnlistener *ev = evconnlistener_new_bind(
                base,                                      ///  libevent的上下文
                ListenCB,                                  /// 接收到连接的回调函数
                &ctx,                                      /// 回调函数获取的参数 arg
                LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, /// 地址重用，evconnlistener关闭同时关闭socket
                10,                                        /// 连接队列大小，对应listen函数
                reinterpret_cast<sockaddr *>(&sa),         /// 绑定的地址和端口
                sizeof(sa));
        if (ev == nullptr)
        {
            std::cout << "evconnlistener_new_bind failed!" << std::endl;
            ctx.close();
            getchar();
            return -1;
        }

        std::cout << "bind port " << PORT << " success." << std::endl;

        for (;;)
        {
            event_base_loop(base, EVLOOP_NONBLOCK);
            std::this_thread::sleep_for(1ms);
        }
        event_base_free(base);
        ctx.close();
    }


#ifdef _WIN32
    WSACleanup();
#endif
    getchar();
    return 0;
}
