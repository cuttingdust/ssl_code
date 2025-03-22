#include <iostream>
#include <openssl/md5.h>
#include <fstream>
#include <thread>

std::string GetFileListHash(const std::string &filePath)
{
    std::string result;
    /// 以二进制方式打开文件
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs)
        return result;

    /// 一次读取多少字节
    int block_size = 128;

    /// 文件读取buf
    unsigned char buf[1024] = { 0 };

    /// hash输出
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
    unsigned char data[]    = "测试md5数据";
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

    for (;;) /// 模拟文件修改
    {
        auto hash = GetFileListHash(filepath);
        if (hash != hash1)
        {
            std::cout << "文件被修改" << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    getchar();
    return 0;
}
