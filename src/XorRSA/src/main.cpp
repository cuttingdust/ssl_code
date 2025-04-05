#include <openssl/rsa.h>
#include <openssl/err.h>
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

int main(int argc, char* argv[])
{
    unsigned char data[1024] = { 0 };
    unsigned char out[2046]  = { 0 };
    for (int i = 0; i < sizeof(data) - 1; ++i)
    {
        data[i] = 'A' + i % 26;
    }
    int data_size = sizeof(data);

    auto r          = CreateRSAKey();
    int  key_size   = RSA_size(r);
    int  block_size = key_size - RSA_PKCS1_PADDING_SIZE;

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

    RSA_free(r);
    getchar();

    return 0;
}
