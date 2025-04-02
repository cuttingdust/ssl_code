#include "xsec.h"

#include <iostream>
#include <fstream>

bool XSecEncryptFile(const std::string &passwd, const std::string &in_filename, const std::string &out_filename,
                     bool is_enc)
{
    std::ifstream ifs(in_filename, std::ios::binary); /// �����ƴ������ļ�
    if (!ifs)
        return false;
    std::ofstream ofs(out_filename, std::ios::binary); /// �����ƴ�С����ļ�
    if (!ofs)
    {
        ifs.close();
        return false;
    }
    XSec sec;
    sec.init(XSec::XAES128_CBC, "1234567812345678", is_enc);

    unsigned char buf[1024] = { 0 };
    unsigned char out[1024] = { 0 };
    int           out_len   = 0;
    /// 1 ���ļ�=��2 �ӽ����ļ�=��3д���ļ�
    while (!ifs.eof())
    {
        /// 1 ���ļ�
        ifs.read((char *)buf, sizeof(buf));
        int count = ifs.gcount();
        if (count <= 0)
            break;
        bool is_end = false;
        if (ifs.eof()) /// �ļ���β
            is_end = true;
        out_len = sec.encrypt(buf, count, out, is_end);
        if (out_len <= 0)
            break;
        ofs.write((char *)out, out_len);
    }
    sec.close();
    ifs.close();
    ofs.close();
    return true;
}

int main(int argc, char *argv[])
{
    {
        auto assert_file  = R"(.\assert\main.cpp)";
        auto encrypt_file = R"(.\assert\main.encrypt.txt)";
        auto decrypt_file = R"(.\assert\main.decrypt.txt)";
        XSecEncryptFile("12345678", assert_file, encrypt_file, true);
        XSecEncryptFile("12345678", encrypt_file, decrypt_file, false);
        getchar();
    }

    unsigned char data[]     = "123456789";
    unsigned char out[1024]  = { 0 };
    unsigned char out2[1024] = { 0 };


    XSec sec;
    /// ECB����
    sec.init(XSec::XDES_ECB, "12345678", true);
    std::cout << "=========== DES ECB =========== " << std::endl;
    std::cout << sizeof(data) << "[" << data << "]" << std::endl;
    int size = sec.encrypt(data, sizeof(data), out);
    std::cout << size << ":" << out << std::endl;

    /// ECB����
    sec.init(XSec::XDES_ECB, "12345678", false);
    size = sec.encrypt(out, size, out2);
    std::cout << size << "|[" << out2 << "]" << std::endl;

    /// CBC����
    sec.init(XSec::XDES_CBC, "12345678", true);
    std::cout << "=========== DES CBC =========== " << std::endl;
    size = sec.encrypt(data, sizeof(data), out);
    std::cout << size << ":" << out << std::endl;

    /// CBC����
    sec.init(XSec::XDES_CBC, "12345678", false);
    size = sec.encrypt(out, size, out2);
    std::cout << size << "|[" << out2 << "]" << std::endl;


    getchar();
    return 0;
}
