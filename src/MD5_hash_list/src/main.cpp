#include <iostream>
#include <openssl/md5.h>
#include <fstream>
#include <thread>

std::string GetFileListHash(const std::string &filePath)
{
    std::string result;
    /// �Զ����Ʒ�ʽ���ļ�
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs)
        return result;

    /// һ�ζ�ȡ�����ֽ�
    int block_size = 128;

    /// �ļ���ȡbuf
    unsigned char buf[1024] = { 0 };

    /// hash���
    unsigned char out[1024] = { 0 };

    while (!ifs.eof())
    {
        ifs.read((char *)buf, block_size);
        int read_size = ifs.gcount();
        if (read_size <= 0)
            break;
        MD5(buf, read_size, out);
        result.insert(result.end(), out, out + 16);
    }
    ifs.close();
    MD5((unsigned char *)result.data(), result.size(), out);

    return std::string(out, out + 16);
}

void PrintHex(const std::string &data)
{
    for (auto c : data)
        std::cout << std::hex << (int)(unsigned char)c;
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    std::cout << "Test  Hash!" << std::endl;
    unsigned char data[]    = "����md5����";
    unsigned char out[1024] = { 0 };
    int           len       = sizeof(data);
    MD5_CTX       c;
    MD5_Init(&c);
    MD5_Update(&c, data, len);
    MD5_Final(out, &c);
    for (int i = 0; i < 16; i++)
        std::cout << std::hex << (int)out[i];
    std::cout << std::endl;
    data[1] = 9;
    MD5(data, len, out);
    for (int i = 0; i < 16; i++)
        std::cout << std::hex << (int)out[i];
    std::cout << std::endl;
    ///////////////////////////////hash_list////////////////////////////////
    std::string filepath = "./assert/main.cpp";
    auto        hash1    = GetFileListHash(filepath);
    PrintHex(hash1);

    for (;;) /// ģ���ļ��޸�
    {
        auto hash = GetFileListHash(filepath);
        if (hash != hash1)
        {
            std::cout << "�ļ����޸�" << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    getchar();
    return 0;
}
