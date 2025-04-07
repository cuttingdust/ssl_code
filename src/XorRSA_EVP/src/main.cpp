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
    /// ��������תΪ������
    unsigned char to[256] = { 0 };
    BN_bn2bin(n, to);
    int byte_size = BN_num_bytes(n);
    for (int i = 0; i < byte_size; i++)
        printf("%02x", to[i]);
    printf("\n");
}

//////////////////////////////////////////////////////
/// ����RSA ��Կ��
/// @return ���ص�pkey�ɵ���EVP_PKEY_free�ͷ�
EVP_PKEY* EvpRsaKey()
{
    /// 1. ����RSA��Կ����������
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /// 2. ��ʼ��RSA��Կ����������
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /// 3 ���ò��� RSA ��Կλ��
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /// 4 ��Կ����
    EVP_PKEY* pkey = NULL;
    /// �ڲ�������EVP_PKEY �ռ�
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    /// �ͷ�������
    EVP_PKEY_CTX_free(ctx);

    /// ��ȡ�����б�
    auto tp = EVP_PKEY_gettable_params(pkey);
    while (tp)
    {
        if (!tp->key)
            break;
        std::cout << tp->key << std::endl;
        tp++;
    }
    /// ��ȡ������ֵ
    BIGNUM* d = 0;
    EVP_PKEY_get_bn_param(pkey, "d", &d);
    PrintBn(d);
    BN_free(d);

    /// �����Կpem�ļ�
    FILE* pubf = fopen(PUBKEY_PEM, "w");
    PEM_write_RSAPublicKey(pubf, EVP_PKEY_get0_RSA(pkey));

    /// �������˽Կpem�ļ�
    FILE* prif = fopen(PRIKEY_PEM, "w");
    PEM_write_RSAPrivateKey(prif, EVP_PKEY_get0_RSA(pkey),
                            NULL, /// ���ܵ�������
                            NULL, /// ��Կ
                            0,    /// ��Կ����
                            NULL, /// ���ܻص�����
                            NULL  /// �û����ݻص�ʹ��
    );


    fclose(pubf);
    fclose(prif);
    return pkey;
}
////////////////////////////////////////////////////////////////////////
/// EVP Rsa����
int EvpRsaEncrypt(const unsigned char* in, int in_size, unsigned char* out)
{
    /// 1 ��ȡpem�еĹ�Կ
    FILE* fp = fopen(PUBKEY_PEM, "r");
    if (!fp)
        return 0;

    RSA* r = NULL;
    PEM_read_RSAPublicKey(fp, &r, NULL, NULL);
    fclose(fp);

    if (!r)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    /// ��Կ�ֽڳ���
    int key_size = RSA_size(r);

    /// 2 ͨ��EVP_PKEY ����EVP_PKEY_CTX������
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, r); /// ����Ϊrsa����Կ
    auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_free(pkey);
    RSA_free(r);

    /// 3 ���ܳ�ʼ��
    EVP_PKEY_encrypt_init(ctx);
    /// ���ݿ��С��������� ��Ĭ��pkcs1�� k-11
    int block_size = key_size - RSA_PKCS1_PADDING_SIZE;
    int out_size   = 0; /// ������ݴ�С Ҳ��������ռ�ƫ��

    /// 4 �������ݿ�
    for (int i = 0; i < in_size; i += block_size)
    {
        /// �����С
        size_t out_len = key_size;
        /// �����С
        size_t bsize = block_size;    /// k-11   128-11 = 117
        if (in_size - i < block_size) /// ���һ������
            bsize = in_size - i;

        if (EVP_PKEY_encrypt(ctx,
                             out + out_size, /// ����ռ�
                             &out_len,       /// ����ռ��С���ռ�Ԥ����С�����룩��ʵ�ʼ��ܺ����ݴ�С�������
                             in + i,         /// ��������
                             bsize) <= 0)    /// �������ݴ�С�����С
        {
            ERR_print_errors_fp(stderr);
            break;
        }
        out_size += out_len;
    }

    EVP_PKEY_CTX_free(ctx);

    return out_size;
}


int EvpRsaDecrypt(const unsigned char* in, int in_size, unsigned char* out)
{
    int out_size = 0;

    /// 1 ��pEM�ļ���ȡ˽Կ
    FILE* fp = fopen(PRIKEY_PEM, "r");
    if (!fp)
        return 0;
    RSA* r = NULL;
    PEM_read_RSAPrivateKey(fp, &r, NULL, NULL);
    if (!r)
    {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    /// ��Կ�ֽڳ���
    int key_size = RSA_size(r);

    /// ����PKEY ������������
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, r);
    auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_free(pkey);
    RSA_free(r);

    /// ���ܳ�ʼ��
    EVP_PKEY_decrypt_init(ctx);

    /// ��������
    for (int i = 0; i < in_size; i += key_size)
    {
        size_t out_len = key_size; /// ��Ҫ��������ռ��С
        if (EVP_PKEY_decrypt(ctx, out + out_size, &out_len, in + i, key_size) <= 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }
        out_size += out_len;
    }
    EVP_PKEY_CTX_free(ctx);

    return out_size;
}

////////////////////////////////////////////////////////////////////////
/// EVP RSA ǩ�� hash=��˽Կǩ��
int EvpSign(const unsigned char* in, int in_size, unsigned char* sign)
{
    /// 1 ��pEM�ļ���ȡ˽Կ
    FILE* fp = fopen(PRIKEY_PEM, "r");
    if (!fp)
        return 0;
    RSA* r = NULL;
    PEM_read_RSAPrivateKey(fp, &r, NULL, NULL);
    if (!r)
    {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    /// ��Կ�ֽڳ���
    // int key_size = RSA_size(r);

    /// 2 ����PKEY ������������
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, r);
    RSA_free(r);

    // auto ctx = EVP_PKEY_CTX_new(pkey, NULL);

    /// ����hash�㷨������
    auto mctx = EVP_MD_CTX_new();
    EVP_SignInit(mctx, EVP_sha512());

    /// ��Ϣ����hashֵ
    EVP_SignUpdate(mctx, in, in_size);
    unsigned int size = in_size;

    /// ȡ��hashֵ����˽Կ����
    EVP_SignFinal(mctx, sign, &size, pkey);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return size;
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

    std::cout << "===============sign====================" << std::endl;
    int sign_size = EvpSign(data, data_size, out);
    std::cout << sign_size << ": " << std::endl;
    std::cout << out << std::endl;
    std::cout << "=======================================" << std::endl;

    /// ����RSA��Կ��
    // auto pKey = EvpRsaKey();
    // EVP_PKEY_free(pKey);

    int en_size = EvpRsaEncrypt(data, data_size, out);
    std::cout << en_size << ":" << out << std::endl;

    int de_size = EvpRsaDecrypt(out, en_size, out2);
    std::cout << de_size << ":" << out2 << std::endl;

    getchar();
    return 0;
}
