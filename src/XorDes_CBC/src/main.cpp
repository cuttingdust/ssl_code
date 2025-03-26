#include <openssl/des.h>

#include <iostream>

/// 交易数据
struct Slip
{
    char      from[16] = { 0 }; /// A=>B 10000
    char      to[16]   = { 0 }; /// 篡改为 B=>A 10000
    long long amount   = 0;
};

static const_DES_cblock key = "1234567";
static DES_key_schedule key_sch;

void EnSlip(const Slip &s, unsigned char *out, int &out_size)
{
    int  size = sizeof(s);
    auto p    = (const unsigned char *)&s;
    auto o    = out;
    DES_set_key(&key, &key_sch);
    for (int i = 0; i < size; i += 8)
    {
        DES_ecb_encrypt((const_DES_cblock *)p, /// 输入数据
                        (DES_cblock *)o,       /// 输出数据
                        &key_sch,              /// 秘钥
                        DES_ENCRYPT            /// 1 加密
        );
        p += 8;
        o += 8;
        out_size += 8;
    }
    /// 补充数据。。。
}

void DeSlip(const unsigned char *in, int size, Slip &s)
{
    auto p = (const unsigned char *)in;
    auto o = (unsigned char *)&s;
    DES_set_key(&key, &key_sch);
    for (int i = 0; i < size; i += 8)
    {
        DES_ecb_encrypt((const_DES_cblock *)p, (DES_cblock *)o, &key_sch, DES_DECRYPT);
        p += 8;
        o += 8;
    }
}

void AttackSlip(unsigned char *out)
{
    /// 修改密文 from 和to 对调
    unsigned char tmp[1024] = { 0 };
    /// from
    memcpy(tmp, out, 16);
    /// to copy from
    memcpy(out, out + 16, 16);
    memcpy(out + 16, tmp, 16);
}

void EnSlipCBC(const Slip &s, unsigned char *out, int &out_size)
{
    int  size = sizeof(s);
    auto p    = (const unsigned char *)&s;
    auto o    = out;
    DES_set_key(&key, &key_sch);
    DES_cblock iv = { 0 }; /// 初始化向量
    out_size      = size;
    /// 数据如果不是8的倍数，会补0
    if (size % 8 != 0)
    {
        /// 补充0
        out_size = size + (8 - size * 8);
    }
    DES_cbc_encrypt(p,          /// 输入
                    o,          /// 输出
                    sizeof(s),  /// 输入数据的大小
                    &key_sch,   /// 秘钥
                    &iv,        /// 初始化向量 DES_cbc_encrypt 调用后值不变
                                /// DES_ncbc_encrypt 保存上次的值
                    DES_ENCRYPT /// 加密
    );
}

void DeSlipCBC(const unsigned char *in, int size, Slip &s)
{
    DES_cblock iv = { 0 }; /// 初始化向量
    DES_set_key(&key, &key_sch);
    /// 如果补0了 解密后无法知道实际大小，需要用户存储原数据大小
    DES_cbc_encrypt(in, (unsigned char *)&s, size, &key_sch, &iv, DES_DECRYPT);
}

int main(int argc, char *argv[])
{
    {
        std::cout << "==========================ebc==========================" << std::endl;
        unsigned char out[1024] = { 0 };
        int           out_size  = 0;
        Slip          s1        = { "USER_A", "USER_B", 10000 };
        std::cout << "s1 from:" << s1.from << std::endl;
        std::cout << "s1 to:" << s1.to << std::endl;
        std::cout << "s1 amount:" << s1.amount << std::endl;
        EnSlip(s1, out, out_size);
        std::cout << "En:" << out_size << "|" << out << std::endl;

        /// 攻击密文
        AttackSlip(out);

        Slip s2;
        DeSlip(out, out_size, s2);
        std::cout << "s2 from:" << s2.from << std::endl;
        std::cout << "s2 to:" << s2.to << std::endl;
        std::cout << "s2 amount:" << s2.amount << std::endl;

        std::cout << "==========================cbc==========================" << std::endl;
        Slip s3;
        EnSlipCBC(s1, out, out_size);
        std::cout << "En:" << out_size << "|" << out << std::endl;

        /// 攻击密文
        AttackSlip(out);

        DeSlipCBC(out, out_size, s3);
        std::cout << "s3 from:" << s3.from << std::endl;
        std::cout << "s3 to:" << s3.to << std::endl;
        std::cout << "s3 amount:" << s3.amount << std::endl;

        std::cout << "=======================================================" << std::endl;
    }

    unsigned char    data[]     = "123456789";
    unsigned char    out[1024]  = { 0 };
    unsigned char    out2[1024] = { 0 };
    const_DES_cblock key        = "1234567";
    DES_key_schedule key_sch;

    /// 1设置秘钥
    DES_set_key(&key, &key_sch);

    /// 数据加密 8字节
    DES_ecb_encrypt((const_DES_cblock *)data, (DES_cblock *)out, &key_sch, DES_ENCRYPT);
    std::cout << out << std::endl;

    /// 数据解密
    DES_ecb_encrypt((const_DES_cblock *)out, (DES_cblock *)out2, &key_sch, DES_DECRYPT);
    std::cout << out2 << std::endl;

    getchar();
    return 0;
}
