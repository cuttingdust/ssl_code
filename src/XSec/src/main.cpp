#include "xsec.h"

#include <iostream>

int main(int argc, char *argv[])
{
    unsigned char data[]     = "123456789";
    unsigned char out[1024]  = { 0 };
    unsigned char out2[1024] = { 0 };


    XSec sec;
    /// ECB加密
    sec.init(XSec::XDES_ECB, "12345678", true);
    std::cout << "=========== DES ECB =========== " << std::endl;
    std::cout << sizeof(data) << "[" << data << "]" << std::endl;
    int size = sec.encrypt(data, sizeof(data), out);
    std::cout << size << ":" << out << std::endl;

    /// ECB解密
    sec.init(XSec::XDES_ECB, "12345678", false);
    size = sec.encrypt(out, size, out2);
    std::cout << size << "|[" << out2 << "]" << std::endl;

    /// CBC加密
    sec.init(XSec::XDES_CBC, "12345678", true);
    std::cout << "=========== DES CBC =========== " << std::endl;
    size = sec.encrypt(data, sizeof(data), out);
    std::cout << size << ":" << out << std::endl;

    /// CBC解密
    sec.init(XSec::XDES_CBC, "12345678", false);
    size = sec.encrypt(out, size, out2);
    std::cout << size << "|[" << out2 << "]" << std::endl;


    getchar();
    return 0;
}
