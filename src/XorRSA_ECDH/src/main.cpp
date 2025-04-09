#include "xecdh.h"
#include <iostream>

int main(int argc, char *argv[])
{
    std::cout << "Test ECDH" << std::endl;

    /// 服务端公钥
    unsigned char spub[1024] = { 0 };

    /// 客户端公钥
    unsigned char cpub[1024] = { 0 };

    XEcdh server;
    XEcdh client;

    /// 服务端和客户端都生成秘钥对
    std::cout << server.createKey() << std::endl;
    int spub_size = server.getPubKey(spub);
    std::cout << "server pubkey:" << spub_size << ":" << spub << std::endl;

    std::cout << client.createKey() << std::endl;
    int cpub_size = client.getPubKey(cpub);
    std::cout << "client pubkey:" << cpub_size << ":" << cpub << std::endl;


    unsigned char ssec[1024] = { 0 };
    unsigned char csec[1024] = { 0 };
    std::cout << "server:" << server.compute(ssec, cpub, cpub_size) << ":" << ssec << std::endl;
    std::cout << "client:" << client.compute(csec, spub, spub_size) << ":" << csec << std::endl;


    getchar();
    return 0;
}
