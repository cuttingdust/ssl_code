#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <iostream>


int main(int argc, char *argv[])
{
    const unsigned char data[]    = "1234567812345678";     /// ����
    unsigned char       out[1024] = { 0 };                  /// ���
    unsigned char       key[128]  = "12345678901234567890"; /// ��Կ
    unsigned char       iv[128]   = { 0 };                  /// ��ʼ������

    /// ����DES 3DES �㷨
    auto cipher = EVP_des_ede3_cbc();
    // auto cipher = EVP_des_cbc();

    /// ��ȡ�㷨�ķ����С����
    int block_size = EVP_CIPHER_block_size(cipher);
    int key_size   = EVP_CIPHER_key_length(cipher);
    int iv_size    = EVP_CIPHER_iv_length(cipher);
    std::cout << "block_size = " << block_size << std::endl;
    std::cout << "key_size = " << key_size << std::endl;
    std::cout << "iv_size = " << iv_size << std::endl;


    /// �ӽ���������
    auto ctx = EVP_CIPHER_CTX_new();

    /// �����㷨��ʼ��
    int re = EVP_CipherInit(ctx, cipher, key, iv,
                            1 /// 1 ��ʾ����
    );
    if (!re)
    {
        ERR_print_errors_fp(stderr);
        getchar();
        return -1;
    }
    std::cout << "EVP_CipherInit success��" << std::endl;


    /// �ͷ�������
    EVP_CIPHER_CTX_free(ctx);

    getchar();
    return 0;
}
