#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <iostream>
#include <fstream>
#include <thread>
#include <vector>

void PrintHex2(const std::string &data)
{
    for (auto c : data)
        std::cout << std::hex << (int)(unsigned char)c;
    std::cout << std::dec << std::endl;
}

void TestEVP()
{
    unsigned char data[128] = "测试EVP SHA3 国密SM3";
    int           data_size = strlen((char *)data);

    /// 初始化EVP上下文
    auto ctx = EVP_MD_CTX_new();
    /*
    const EVP_MD *EVP_md5(void);
    const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_sha512_224(void);
const EVP_MD *EVP_sha512_256(void);
const EVP_MD *EVP_sha3_224(void);
const EVP_MD *EVP_sha3_256(void);
const EVP_MD *EVP_sha3_384(void);
const EVP_MD *EVP_sha3_512(void);
const EVP_MD *EVP_shake128(void);
const EVP_MD *EVP_shake256(void);
const EVP_MD *EVP_sm3(void); //1.1.1 版本开始支持
    */

    auto evp_md = EVP_sha3_512();

    /// hash初始化
    EVP_DigestInit_ex(ctx, evp_md, NULL);

    ///计算hash值
    EVP_DigestUpdate(ctx, data, data_size);

    /// 获取结果
    unsigned char out[64]  = { 0 };
    unsigned int  out_size = 0;
    EVP_DigestFinal_ex(ctx, out, &out_size);

    std::cout << "SHA3-512:";
    std::cout << "(" << out_size << ")";
    PrintHex2(std::string(out, out + out_size));

    /// 清理上下文
    EVP_MD_CTX_free(ctx);

    /// 调用EVP简化接口编码 国密SM3
    EVP_Digest(data, data_size, out, &out_size, EVP_sm3(), NULL);

    std::cout << "国密SM3：";
    std::cout << "(" << out_size << ")";
    PrintHex2(std::string(out, out + out_size));
}


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

constexpr auto HMAC_KEY  = "123456";
constexpr auto HASH_SIZE = 32;
std::string    GetHMAC1()
{
    auto         &key       = HMAC_KEY;
    unsigned char data[128] = "测试HMAC";
    int           data_size = strlen((char *)data);
    unsigned char mac[1024] = { 0 };
    unsigned int  mac_size  = 0;
    HMAC(EVP_sha256(),               /// 选用的Hash 算法
         HMAC_KEY, strlen(HMAC_KEY), /// key
         data, data_size,            /// MSG
         mac, &mac_size);            /// mac 消息认证码
    std::string msg(mac, mac + mac_size);
    msg.append(data, data + data_size);

    return msg;
}

void TestHMAC()
{
    unsigned char out[1024] = { 0 };
    unsigned int  out_size  = 0;

    auto msg1 = GetHMAC1();

    const char *data      = msg1.data() + HASH_SIZE;
    int         data_size = msg1.size() - HASH_SIZE; ///去掉头部

    /// 收到的消息认证码
    std::string hmac(msg1.begin(), msg1.begin() + HASH_SIZE);

    /// 验证消息完整和认证
    HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), (unsigned char *)data, data_size, out, &out_size);

    /// 服务端生成的消息认证码
    std::string smac(out, out + out_size);
    if (hmac == smac)
    {
        std::cout << "hmac success! no change!" << std::endl;
    }
    else
    {
        std::cout << "hmac failed! mac changed! " << std::endl;
    }

    /// 篡改数据
    msg1[33] = 'B';

    /// 验证消息完整和认证
    HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), (unsigned char *)data, data_size, out, &out_size);

    /// 服务端生成的消息认证码
    smac = std::string(out, out + out_size);
    if (hmac == smac)
    {
        std::cout << "hmac success! no change!" << std::endl;
    }
    else
    {
        std::cout << "hmac failed! mac changed! " << std::endl;
    }
}

int main(int argc, char *argv[])
{
    TestHMAC();
    getchar();
    TestEVP();
    getchar();
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
