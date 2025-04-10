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
#include <string>
#include <iostream>
#include <string.h>
#include <stdlib.h>


#define PORT 20030

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

            /// ¿Í»§¶Ë
            std::string ip   = "127.0.0.1";
            int         sock = socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_addr.s_addr = inet_addr(ip.c_str());
            sa.sin_port        = htons(PORT);

            int re = connect(sock, reinterpret_cast<sockaddr *>(&sa), sizeof(sa));
            if (re != 0)
            {
                std::cout << "connect " << ip << ":" << PORT << " faield!" << std::endl;
                getchar();
                return -1;
            }

            std::cout << "connect " << ip << ":" << PORT << " success!" << std::endl;
        }
    }
    else
    {
        printf("Server start.\n");

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

        listen(accept_sock, 10);
        std::cout << "start listen port " << PORT << std::endl;

        for (;;)
        {
            int client_socket = accept(accept_sock, 0, 0);
            if (client_socket <= 0)
                break;
            std::cout << "accept socket" << std::endl;
        }
    }


    std::cout << "hello world" << std::endl;

    return 0;
}
