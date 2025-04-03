#include <openssl/rsa.h>

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
    auto r = CreateRSAKey();

    RSA_free(r);
    getchar();

    return 0;
}
