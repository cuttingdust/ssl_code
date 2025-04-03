#include <openssl/rsa.h>

#include <iostream>

void PrintBn(const BIGNUM* n)
{
    /// 大数对象转为二进制
    unsigned char to[256] = { 0 };
    BN_bn2bin(n, to);
    int byte_size = BN_num_bytes(n);
    for (int i = 0; i < byte_size; i++)
        printf("%02x", to[i]);
    printf("\n");
}

/// 生成RSA密钥对
RSA* CreateRSAKey()
{
    /// 存放rsa密钥对
    RSA* r = RSA_new();

    /// 公钥指数（大质数）  公钥（E N）
    BIGNUM* e = BN_new();

    /// 生成公钥指数E
    /// 公钥指数 使用默认值 RSA_F4 65537,
    /// 也可以采用随机值，性能不可控制
    BN_set_word(e, RSA_F4);


    /// 生成私钥指数D和  模数N(N=p*q  pq随机大质数)
    /// 内部调用伪随机产生 N和D
    RSA_generate_key_ex(r,   /// 输出RSA密钥对
                        512, /// 密钥的比特位
                        e,   /// 公钥指数
                        NULL /// 密钥生成的回调函数
    );
    BN_free(e);


    {
        /// 模数N模数N
        const auto n = RSA_get0_n(r);

        /// 公钥指数   明文^公钥指数E  % N（模数） = 密文
        const auto e = RSA_get0_e(r);

        /// 私钥指数   密文^私钥指数E  % N（模数） = 明文
        const auto d = RSA_get0_d(r);

        std::cout << "n = ";
        PrintBn(n);

        std::cout << "e = ";
        PrintBn(e);

        std::cout << "d = ";
        PrintBn(d);
    }
    return r;
}

int main(int argc, char* argv[])
{
    auto r = CreateRSAKey();

    RSA_free(r);
    getchar();

    return 0;
}
