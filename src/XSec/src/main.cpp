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


class TestCipher
{
public:
    TestCipher() = default;
    ~TestCipher()
    {
        close();
    }

public:
    void close()
    {
        delete in_;
        in_ = nullptr;
        delete de_;
        de_ = nullptr;
        delete en_;
        en_ = nullptr;
    }

    void init(int data_size)
    {
        close();

        data_size_ = data_size;
        in_        = new unsigned char[data_size];
        en_        = new unsigned char[data_size + 128];
        de_        = new unsigned char[data_size + 128];

        /// �������ݸ���ֵ
        unsigned int data = 1;
        for (int i = 0; i < data_size; i += sizeof(data))
        {
            memcpy(in_ + i, &data, sizeof(data));
            data++;
        }
        memset(en_, 0, data_size + 128);
        memset(de_, 0, data_size + 128);
    }

    void Test(const XSec::XSecType &type, std::string type_name)
    {
        memset(en_, 0, data_size_ + 128);
        memset(de_, 0, data_size_ + 128);
        std::cout << " ============ " << type_name << " ============ " << std::endl;
        XSec sec;

        /// ����
        sec.init(type, passwd, true);
        auto start   = clock();
        int  en_size = sec.encrypt(in_, data_size_, en_);
        auto end     = clock();
        std::cout << en_size << "���ܻ���ʱ�䣺" << (double)((end - start) / (double)CLOCKS_PER_SEC) << "��"
                  << std::endl;

        /// ����
        sec.init(type, passwd, false);
        start       = clock();
        int de_size = sec.encrypt(en_, en_size, de_);
        end         = clock();
        std::cout << de_size << "���ܻ���ʱ�䣺" << (double)((end - start) / (double)CLOCKS_PER_SEC) << "��"
                  << std::endl;
    }

private:
    int            data_size_ = 0;                                  /// �������ֽ���
    unsigned char *in_        = nullptr;                            /// ��������
    unsigned char *en_        = nullptr;                            /// ���ܺ�����
    unsigned char *de_        = nullptr;                            /// ���ܺ�����
    std::string    passwd     = "12345678ABCDEFGHabcdefgh!@#$%^&*"; ///���� ��Ӧ����ǿ��
};

//ci.Test(XDES_ECB, "XDES_ECB");
#define TEST_CIPHER(s) ci.Test(XSec::s, #s)

int main(int argc, char *argv[])
{
    {
        TestCipher ci;
        ci.init(1024 * 1024 * 100); /// 100M

        TEST_CIPHER(XDES_ECB);
        TEST_CIPHER(XDES_CBC);

        TEST_CIPHER(X3DES_ECB);
        TEST_CIPHER(X3DES_CBC);

        TEST_CIPHER(XAES128_ECB);
        TEST_CIPHER(XAES128_CBC);

        TEST_CIPHER(XAES192_ECB);
        TEST_CIPHER(XAES192_CBC);

        TEST_CIPHER(XAES256_ECB);
        TEST_CIPHER(XAES256_CBC);

        TEST_CIPHER(XSM4_ECB);
        TEST_CIPHER(XSM4_CBC);

        getchar();
    }

    {
        auto assert_file  = R"(.\assert\main.cpp)";
        auto encrypt_file = R"(.\assert\main.encrypt.txt)";
        auto decrypt_file = R"(.\assert\main.decrypt.txt)";

        XSecEncryptFile("12345678", assert_file, encrypt_file, true);
        XSecEncryptFile("12345678", encrypt_file, decrypt_file, false);

        getchar();
    }

    {
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
    }


    return 0;
}
