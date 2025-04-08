#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <iostream>

#define PUBKEY_PEM R"(./assert/pubkey.pem)"
#define PRIKEY_PEM R"(./assert/prikey.pem)"

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

EVP_PKEY* EccKey()
{
    /// 打印所有支持的椭圆曲线
    int               cur_len = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve* curves  = new EC_builtin_curve[cur_len];
    EC_get_builtin_curves(curves, cur_len);
    for (int i = 0; i < cur_len; i++)
    {
        std::cout << i + 1 << "|" << curves[i].nid << ":" << curves[i].comment << std::endl;
    }
    delete[] curves;

    /// 选择椭圆曲线
    auto group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /// 创建 EC 密钥上下文
    auto key = EC_KEY_new();
    EC_KEY_set_group(key, group);

    /// 生成密钥
    if (EC_KEY_generate_key(key) != 1)
    {
        EC_KEY_free(key);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /// 检查密钥
    if (EC_KEY_check_key(key) != 1)
    {
        EC_KEY_free(key);
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    std::cout << "EC_KEY_check_key success!" << std::endl;

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, key);
    EC_KEY_free(key);

    return pkey;
}

////////////////////////////////////////////////////////////////////////
/// EVP Rsa加密
int EvpRsaEncrypt(const unsigned char* in, int in_size, unsigned char* out, EVP_PKEY* pkey)
{
    if (!in || in_size <= 0 || !out || !pkey)
        return -1;

    /// ecc加密上下文初始化
    auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /// 除了sm2 其他的一些算法会失败
    int re = EVP_PKEY_encrypt_init(ctx);
    if (re != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    /// ecc 加密
    size_t out_len = sizeof(out);
    if (EVP_PKEY_encrypt(ctx, out, &out_len, in, in_size) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return out_len;
}


int EvpRsaDecrypt(const unsigned char* in, int in_size, unsigned char* out, EVP_PKEY* pkey)
{
    if (!in || in_size <= 0 || !out || !pkey)
        return -1;

    /// ecc加密上下文初始化
    auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /// 除了sm2 其他的一些算法会失败
    int re = EVP_PKEY_decrypt_init(ctx);
    if (re != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    /// ecc 加密
    size_t out_len = in_size;
    if (EVP_PKEY_decrypt(ctx, out, &out_len, in, in_size) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    return out_len;
}

////////////////////////////////////////////////////////////////////////
/// EVP RSA 签名 hash=》私钥签名
int EvpSign(const unsigned char* in, int in_size, unsigned char* sign, EVP_PKEY* pkey)
{
    if (!pkey || !in || !sign)
        return -1; /// 返回错误

    /// 创建消息摘要上下文
    auto mctx = EVP_MD_CTX_new();
    if (!mctx)
    {
        ERR_print_errors_fp(stderr);
        return -1; /// 返回错误
    }

    /// 初始化签名上下文
    if (EVP_SignInit(mctx, EVP_sm3()) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mctx);
        return -1; /// 返回错误
    }

    /// k私钥 h消息散列 r随机数
    /// rG = (x,y)
    /// s=r^-1(h+kx)  (rG，s)

    /// 更新数据
    if (EVP_SignUpdate(mctx, in, in_size) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mctx);
        return -1; /// 返回错误
    }

    /// 获取签名的大小
    unsigned int sign_len = EVP_PKEY_size(pkey);

    /// 生成签名
    if (EVP_SignFinal(mctx, sign, &sign_len, pkey) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mctx);
        return -1; /// 返回错误
    }

    /// 释放资源
    EVP_MD_CTX_free(mctx);
    return sign_len; /// 返回签名长度
}

////////////////////////////////////////////////////////////////////////
/// EVP RSA 验签 hash=》公钥验签
bool EvpRsaVerify(const unsigned char* in, int in_size, const unsigned char* sign, int sign_size, EVP_PKEY* pkey)
{
    if (!pkey || !in || !sign)
        return false; /// 返回错误

    /// 验签 hash算法
    auto mctx = EVP_MD_CTX_new();
    EVP_VerifyInit(mctx, EVP_sm3());

    /// 生成单向散列
    EVP_VerifyUpdate(mctx, in, in_size);

    /// =1 验签成功
    /// s签名  kG 公钥
    /// s^-1hG + s^-1xkG

    /// 公钥解密签名 ，对比生成的单向散列
    int re = EVP_VerifyFinal(mctx, /// 上下文中存放单向散列
                             sign, /// 签名
                             sign_size,
                             pkey); /// 公钥解密
    EVP_MD_CTX_free(mctx);

    if (re == 1)
        return true;

    return false;
}

int main(int argc, char* argv[])
{
    unsigned char data[1024] = { 0 };
    unsigned char out[2046]  = { 0 };
    unsigned char out2[2046] = { 0 };
    for (int i = 0; i < sizeof(data) - 1; ++i)
    {
        data[i] = 'A' + i % 26;
    }
    int data_size = sizeof(data);

    auto pkey = EccKey();

    std::cout << "===============sign====================" << std::endl;
    int sign_size = EvpSign(data, data_size, out, pkey);
    std::cout << sign_size << ": " << std::endl;
    std::cout << out << std::endl;
    std::cout << "=======================================" << std::endl;

    if (EvpRsaVerify(data, data_size, out, sign_size, pkey))
    {
        std::cout << "verify ok" << std::endl;
    }
    else
    {
        std::cout << "verify failed";
    }

    // data[0] = 'C'; /// 数据变更
    out[0] = 'C'; /// hash变更

    if (EvpRsaVerify(data, data_size, out, sign_size, pkey))
    {
        std::cout << "verify ok" << std::endl;
    }
    else
    {
        std::cout << "verify failed" << std::endl;
    }

    int out_len = EvpRsaEncrypt(data, data_size, out, pkey);
    std::cout << out_len << ": " << out << std::endl;

    int out2_len = EvpRsaDecrypt(out, out_len, out2, pkey);
    std::cout << out2_len << ": " << out2 << std::endl;

    EVP_PKEY_free(pkey);

    getchar();
    return 0;
}
