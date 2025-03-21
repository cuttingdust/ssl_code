#include <iostream>
#include <openssl/md5.h>

void PrintHex(const std::string &data)
{
    for (auto c : data)
        std::cout << std::hex << (int)(unsigned char)c;
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    std::cout << "Test  Hash!" << std::endl;
    unsigned char data[]    = "²âÊÔmd5Êý¾Ý";
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

    getchar();
    return 0;
}
