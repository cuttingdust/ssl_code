#include <iostream>

constexpr auto XOR_BLOCK = 8;

/// \brief  �ԳƼӽ�������
/// \param data  ��������
/// \param data_size  �������ݴ�С
/// \param out  �������
/// \param pass  ��Կ
/// \param pass_size  ��Կ����
/// \return  �ӽ��ܺ����ݴ�С
int XorCipher(const unsigned char *data, int data_size, unsigned char *out, const unsigned char *pass, int pass_size)
{
    /// ��ʼ����Կ
    auto p = *(unsigned long long *)pass;

    /// ����Դת����8�ֽ���������
    auto d = (unsigned long long *)data;
    /// �������
    auto o = (unsigned long long *)out;
    /// ���ݷ��鴦��
    int i = 0;
    for (; i < data_size / XOR_BLOCK; i++)
    {
        /// XOR �������
        o[i] = (d[i] ^ p);
    }

    int re_size = data_size;
    return re_size;
}

int main(int argc, char *argv[])
{
    unsigned char data[]     = "���Լӽ�������TEST";
    unsigned char out[1024]  = { 0 };
    unsigned char out2[1024] = { 0 };

    unsigned char pass[]    = "123456";
    int           pass_size = strlen((char *)pass);
    int           len       = XorCipher(data, sizeof(data), out, pass, pass_size);
    std::cout << len << "|" << out << std::endl;
    len = XorCipher(out, len, out2, pass, pass_size);
    std::cout << len << ":" << out2 << std::endl;

    return 0;
}
