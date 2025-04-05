#include <openssl/evp.h>
#include <openssl/err.h>

#include <iostream>


int main(int argc, char *argv[])
{
    const unsigned char data[] = "1234567812345"; /// 输入
    // const unsigned char data[]    = "1234567812345678"; /// 输入
    int data_size = strlen((char *)data);
    std::cout << "data_size = " << data_size << std::endl;
    unsigned char out[1024] = { 0 };                  /// 输出
    unsigned char key[128]  = "12345678901234567890"; /// 秘钥
    unsigned char iv[128]   = { 0 };                  /// 初始化向量

    /// 三重DES 3DES 算法
    auto cipher = EVP_des_ede3_cbc();
    // auto cipher = EVP_des_cbc();

    /// 获取算法的分组大小（）
    int block_size = EVP_CIPHER_block_size(cipher);
    int key_size   = EVP_CIPHER_key_length(cipher);
    int iv_size    = EVP_CIPHER_iv_length(cipher);
    std::cout << "block_size = " << block_size << std::endl;
    std::cout << "key_size = " << key_size << std::endl;
    std::cout << "iv_size = " << iv_size << std::endl;


    /// 加解密上下文
    auto ctx = EVP_CIPHER_CTX_new();

    /// 加密算法初始化
    int re = EVP_CipherInit(ctx, cipher, key, iv,
                            1 /// 1 表示加密
    );
    if (!re)
    {
        ERR_print_errors_fp(stderr);
        getchar();
        return -1;
    }
    std::cout << "EVP_CipherInit success！" << std::endl;

    /// 默认 PKCS7 补充大小 EVP_PADDING_PKCS7
    /// 关闭自动填充
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    // EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    int out_size = 0;

    /// 只处理分组大小得到数据,如果取消自动填充，多余数据丢弃
    /// 如果自动填充，则在EVP_CipherFinal 中获取数据
    EVP_CipherUpdate(ctx,
                     out,       /// 输出
                     &out_size, /// 输出数据大小
                     data,      /// 输入数据
                     data_size);
    std::cout << "EVP_CipherUpdate size:" << out_size << std::endl;

    /// 取出最后一块数据（需要填充的），或者是padding补充的数据
    int padding_size = 0;
    EVP_CipherFinal(ctx, out + out_size, &padding_size);
    std::cout << "padding_size = " << padding_size << std::endl;
    out_size += padding_size;
    std::cout << out_size << ":" << out << std::endl;

    //////////////////////////////////////////////////////////////////
    /// 解密数据 使用原来的ctx
    re = EVP_CipherInit(ctx, cipher, key, iv,
                        0 /// 0表示解密
    );
    if (!re)
    {
        ERR_print_errors_fp(stderr);
    }

    /// 多余的数据会被舍弃掉 但是补全策略需要一致
    // EVP_CIPHER_CTX_set_padding(ctx, 0);

    /// 解密密文后存放的明文
    unsigned char out2[1024] = { 0 };
    int           out2_size  = 0;
    /// 解密数据 填充数据取不到
    EVP_CipherUpdate(ctx, out2, &out2_size, /// 输入密文数据
                     out, out_size);        /// 输出解密后明文
    std::cout << "EVP_CipherUpdate out2_size = " << out2_size << std::endl;

    /// 取出填充数据
    EVP_CipherFinal(ctx, out2 + out2_size, &padding_size);
    std::cout << "EVP_CipherFinal padding_size=" << padding_size << std::endl;
    out2_size += padding_size;
    std::cout << out2_size << ":" << out2 << "|" << std::endl;

    /// 释放上下文
    EVP_CIPHER_CTX_free(ctx);

    getchar();
    return 0;
}
