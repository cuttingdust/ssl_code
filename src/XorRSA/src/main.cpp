#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
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

//////////////////////////////////////////////////////
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

int RsaEncrypt(RSA* r, unsigned char* data, int data_size, unsigned char* out)
{
    int key_size   = RSA_size(r);
    int block_size = key_size - RSA_PKCS1_PADDING_SIZE;

    std::cout << "rsa key size = " << key_size << std::endl;

    int out_size = 0;

    for (int i = 0; i < data_size; i += block_size)
    {
        int en_size = block_size;
        if (data_size - i < block_size)
        {
            en_size = data_size - i;
        }


        int out_off = i + RSA_PKCS1_PADDING_SIZE * (i / block_size);

        int re = RSA_public_encrypt(en_size,          /// 数据大小
                                    data + i,         /// 输入数据
                                    out + out_off,    /// 输出数据
                                    r,                /// 私钥 公钥
                                    RSA_PKCS1_PADDING /// 填充方式
        );
        if (re < 0)
        {
            ERR_print_errors_fp(stderr);
        }

        out_size = out_off + key_size;
        std::cout << re << std::endl;
    }

    std::cout << "out_size = " << out_size << std::endl;

    return out_size;
}

int RsaDecrypt(RSA* r, unsigned char* data, int data_size, unsigned char* out)
{
    int key_size = RSA_size(r);
    int out_off  = 0;
    for (int i = 0; i < data_size; i += key_size)
    {
        int re = RSA_private_decrypt(key_size, data + i, out + out_off, r, RSA_PKCS1_PADDING);
        if (re < 0)
        {
            ERR_print_errors_fp(stderr);
        }
        out_off += re;
    }
    return out_off;
}

//////////////////////////////////////////////////////
/// 生成RSA 秘钥对
/// @return 返回的pkey由调用EVP_PKEY_free释放
EVP_PKEY* EvpRsaKey()
{
    /// 1. 创建RSA公钥加密上下文
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /// 2. 初始化RSA公钥加密上下文
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /// 3 设置参数 RSA 秘钥位数
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /// 4 秘钥生成
    EVP_PKEY* pkey = NULL;
    /// 内部会生成EVP_PKEY 空间
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    /// 释放上下文
    EVP_PKEY_CTX_free(ctx);

    /// 获取参数列表
    auto tp = EVP_PKEY_gettable_params(pkey);
    while (tp)
    {
        if (!tp->key)
            break;
        std::cout << tp->key << std::endl;
        tp++;
    }
    /// 获取参数的值
    BIGNUM* d = 0;
    EVP_PKEY_get_bn_param(pkey, "d", &d);
    PrintBn(d);
    BN_free(d);

    /// 输出公钥pem文件
    FILE* pubf = fopen("./assert/pubkey.pem", "w");
    PEM_write_RSAPublicKey(pubf, EVP_PKEY_get0_RSA(pkey));

    /// 输出明文私钥pem文件
    FILE* prif = fopen("./assert/prikey.pem", "w");
    PEM_write_RSAPrivateKey(prif, EVP_PKEY_get0_RSA(pkey),
                            NULL, /// 加密的上下文
                            NULL, /// 秘钥
                            0,    /// 秘钥长度
                            NULL, /// 加密回调函数
                            NULL  /// 用户数据回调使用
    );


    fclose(pubf);
    fclose(prif);
    return pkey;
}


int main(int argc, char* argv[])
{
    // unsigned char data[1024] = { 0 };
    // unsigned char out[2046]  = { 0 };
    // unsigned char out2[2046] = { 0 };
    // for (int i = 0; i < sizeof(data) - 1; ++i)
    // {
    //     data[i] = 'A' + i % 26;
    // }
    // int data_size = sizeof(data);
    //
    // auto r        = CreateRSAKey();
    // int  en_size = RsaEncrypt(r, data, data_size, out);
    // std::cout << en_size << ": " << out << std::endl;
    //
    // /// 存放解密私钥
    // RSA* rd = RSA_new();
    // /// n d e
    // auto n = BN_new();
    // auto d = BN_new();
    // auto e = BN_new();
    //
    // BN_copy(n, RSA_get0_n(r));
    // BN_copy(e, RSA_get0_e(r));
    // BN_copy(d, RSA_get0_d(r));
    // RSA_set0_key(rd, n, e, d);
    // int de_size = RsaDecrypt(rd, out, en_size, out2);
    // std::cout << de_size << ": " << out2 << std::endl;
    //
    // RSA_free(r);
    // RSA_free(rd);
    // getchar();

    auto pKey = EvpRsaKey();

    EVP_PKEY_free(pKey);
    getchar();
    return 0;
}
