#include <iostream>
#include <openssl/md5.h>
#include <fstream>
#include <thread>
#include <vector>
#include <openssl/sha.h>

void TestBit()
{
    unsigned char data[128] = "测试比特币挖矿，模拟交易链";
    int           data_size = strlen((char *)data);
    unsigned int  nonce     = 0; /// 找到nonce
    unsigned char md1[1024] = { 0 };
    unsigned char md2[1024] = { 0 };
    for (;;)
    {
        nonce++;
        memcpy(data + data_size, &nonce, sizeof(nonce));
        SHA256(data, data_size + sizeof(nonce), md1);
        SHA256(md1, 64, md2);
        /// 工作量 难度 /// 317 /// 1223339 /// 3998170
        if (md2[0] == 0 && md2[1] == 0 && md2[2] == 0)
            break;
    }
    std::cout << "nonce = " << nonce << std::endl;
}

/// 文件可信树Hash
/*
                    A               A
                  /  \            /   \
                B     C         B       C
               / \    |        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 6     1 2 3 4 5 6 5 6
*/
std::string GetFileMerkleHash(const std::string &filepath)
{
    std::string hash;

    std::vector<std::string> hash_list;
    std::ifstream            ifs(filepath, std::ios::binary);
    if (!ifs)
        return hash;
    unsigned char buf[1024]  = { 0 };
    unsigned char out[1024]  = { 0 };
    int           block_size = 128;
    while (!ifs.eof())
    {
        ifs.read((char *)buf, block_size);
        int read_size = ifs.gcount();
        if (read_size <= 0)
            break;
        SHA1(buf, read_size, out);
        /// 写入叶子节点的hash值
        hash_list.emplace_back(out, out + 20);
    }

    while (hash_list.size() > 1) /// ==1 表示已经计算到root节点
    {
        /// 不是二的倍数补节点 （二叉树）
        if (hash_list.size() & 1)
        {
            ///补充最后一个节点
            hash_list.push_back(hash_list.back());
        }
        /// 把两两节点的hash结果还写入hashes中，
        for (int i = 0; i < hash_list.size() / 2; i++)
        {
            /// 两个节点拼起来 i表示的是父节点
            std::string tmp_hash = hash_list[i * 2];
            tmp_hash += hash_list[i * 2 + 1];
            SHA1((unsigned char *)tmp_hash.data(), tmp_hash.size(), out);
            /// 写入结果
            hash_list[i] = std::string(out, out + 20);
        }
        /// hash列表删除上一次多余的hash值
        hash_list.resize(hash_list.size() / 2);
    }
    if (hash_list.empty())
        return hash;
    return hash_list[0];
}

std::string GetFileListHash(const std::string &filePath)
{
    std::string hash;
    /// 以二进制方式打开文件
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs)
        return hash;

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
        hash.insert(hash.end(), out, out + 16);
    }
    ifs.close();
    MD5((unsigned char *)hash.data(), hash.size(), out);

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
    TestBit();
    getchar();
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

    for (;;)
    {
        auto hash = GetFileListHash(filepath);
        /////////////////////////////merkle_hash_tree///////////////////////////
        auto thash = GetFileMerkleHash(filepath);
        std::cout << "HashList:\t";
        PrintHex(hash);
        std::cout << "MerkleTree:\t";
        PrintHex(thash);
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
