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
    /// ��������תΪ������
    unsigned char to[256] = { 0 };
    BN_bn2bin(n, to);
    int byte_size = BN_num_bytes(n);
    for (int i = 0; i < byte_size; i++)
        printf("%02x", to[i]);
    printf("\n");
}

//////////////////////////////////////////////////////
/// ����RSA��Կ��
RSA* CreateRSAKey()
{
    /// ���rsa��Կ��
    RSA* r = RSA_new();

    /// ��Կָ������������  ��Կ��E N��
    BIGNUM* e = BN_new();

    /// ���ɹ�Կָ��E
    /// ��Կָ�� ʹ��Ĭ��ֵ RSA_F4 65537,
    /// Ҳ���Բ������ֵ�����ܲ��ɿ���
    BN_set_word(e, RSA_F4);


    /// ����˽Կָ��D��  ģ��N(N=p*q  pq���������)
    /// �ڲ�����α������� N��D
    RSA_generate_key_ex(r,   /// ���RSA��Կ��
                        512, /// ��Կ�ı���λ
                        e,   /// ��Կָ��
                        NULL /// ��Կ���ɵĻص�����
    );
    BN_free(e);


    {
        /// ģ��Nģ��N
        const auto n = RSA_get0_n(r);

        /// ��Կָ��   ����^��Կָ��E  % N��ģ���� = ����
        const auto e = RSA_get0_e(r);

        /// ˽Կָ��   ����^˽Կָ��E  % N��ģ���� = ����
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

        int re = RSA_public_encrypt(en_size,          /// ���ݴ�С
                                    data + i,         /// ��������
                                    out + out_off,    /// �������
                                    r,                /// ˽Կ ��Կ
                                    RSA_PKCS1_PADDING /// ��䷽ʽ
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
    FILE* pubf = fopen("./assert/pubkey.pem", "w");
    PEM_write_RSAPublicKey(pubf, EVP_PKEY_get0_RSA(pkey));

    /// �������˽Կpem�ļ�
    FILE* prif = fopen("./assert/prikey.pem", "w");
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
    // /// ��Ž���˽Կ
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
