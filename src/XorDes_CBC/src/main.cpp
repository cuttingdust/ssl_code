#include <openssl/des.h>

#include <iostream>

/// ��������
struct Slip
{
    char      from[16] = { 0 }; /// A=>B 10000
    char      to[16]   = { 0 }; /// �۸�Ϊ B=>A 10000
    long long amount   = 0;
};

static const_DES_cblock key = "1234567";
static DES_key_schedule key_sch;

void EnSlip(const Slip &s, unsigned char *out, int &out_size)
{
    int  size = sizeof(s);
    auto p    = (const unsigned char *)&s;
    auto o    = out;
    DES_set_key(&key, &key_sch);
    for (int i = 0; i < size; i += 8)
    {
        DES_ecb_encrypt((const_DES_cblock *)p, /// ��������
                        (DES_cblock *)o,       /// �������
                        &key_sch,              /// ��Կ
                        DES_ENCRYPT            /// 1 ����
        );
        p += 8;
        o += 8;
        out_size += 8;
    }
    /// �������ݡ�����
}

void DeSlip(const unsigned char *in, int size, Slip &s)
{
    auto p = (const unsigned char *)in;
    auto o = (unsigned char *)&s;
    DES_set_key(&key, &key_sch);
    for (int i = 0; i < size; i += 8)
    {
        DES_ecb_encrypt((const_DES_cblock *)p, (DES_cblock *)o, &key_sch, DES_DECRYPT);
        p += 8;
        o += 8;
    }
}

void AttackSlip(unsigned char *out)
{
    /// �޸����� from ��to �Ե�
    unsigned char tmp[1024] = { 0 };
    /// from
    memcpy(tmp, out, 16);
    /// to copy from
    memcpy(out, out + 16, 16);
    memcpy(out + 16, tmp, 16);
}

void EnSlipCBC(const Slip &s, unsigned char *out, int &out_size)
{
    int  size = sizeof(s);
    auto p    = (const unsigned char *)&s;
    auto o    = out;
    DES_set_key(&key, &key_sch);
    DES_cblock iv = { 0 }; /// ��ʼ������
    out_size      = size;
    /// �����������8�ı������Ჹ0
    if (size % 8 != 0)
    {
        /// ����0
        out_size = size + (8 - size * 8);
    }
    DES_cbc_encrypt(p,          /// ����
                    o,          /// ���
                    sizeof(s),  /// �������ݵĴ�С
                    &key_sch,   /// ��Կ
                    &iv,        /// ��ʼ������ DES_cbc_encrypt ���ú�ֵ����
                                /// DES_ncbc_encrypt �����ϴε�ֵ
                    DES_ENCRYPT /// ����
    );
}

void DeSlipCBC(const unsigned char *in, int size, Slip &s)
{
    DES_cblock iv = { 0 }; /// ��ʼ������
    DES_set_key(&key, &key_sch);
    /// �����0�� ���ܺ��޷�֪��ʵ�ʴ�С����Ҫ�û��洢ԭ���ݴ�С
    DES_cbc_encrypt(in, (unsigned char *)&s, size, &key_sch, &iv, DES_DECRYPT);
}

int main(int argc, char *argv[])
{
    {
        std::cout << "==========================ebc==========================" << std::endl;
        unsigned char out[1024] = { 0 };
        int           out_size  = 0;
        Slip          s1        = { "USER_A", "USER_B", 10000 };
        std::cout << "s1 from:" << s1.from << std::endl;
        std::cout << "s1 to:" << s1.to << std::endl;
        std::cout << "s1 amount:" << s1.amount << std::endl;
        EnSlip(s1, out, out_size);
        std::cout << "En:" << out_size << "|" << out << std::endl;

        /// ��������
        AttackSlip(out);

        Slip s2;
        DeSlip(out, out_size, s2);
        std::cout << "s2 from:" << s2.from << std::endl;
        std::cout << "s2 to:" << s2.to << std::endl;
        std::cout << "s2 amount:" << s2.amount << std::endl;

        std::cout << "==========================cbc==========================" << std::endl;
        Slip s3;
        EnSlipCBC(s1, out, out_size);
        std::cout << "En:" << out_size << "|" << out << std::endl;

        /// ��������
        AttackSlip(out);

        DeSlipCBC(out, out_size, s3);
        std::cout << "s3 from:" << s3.from << std::endl;
        std::cout << "s3 to:" << s3.to << std::endl;
        std::cout << "s3 amount:" << s3.amount << std::endl;

        std::cout << "=======================================================" << std::endl;
    }

    unsigned char    data[]     = "123456789";
    unsigned char    out[1024]  = { 0 };
    unsigned char    out2[1024] = { 0 };
    const_DES_cblock key        = "1234567";
    DES_key_schedule key_sch;

    /// 1������Կ
    DES_set_key(&key, &key_sch);

    /// ���ݼ��� 8�ֽ�
    DES_ecb_encrypt((const_DES_cblock *)data, (DES_cblock *)out, &key_sch, DES_ENCRYPT);
    std::cout << out << std::endl;

    /// ���ݽ���
    DES_ecb_encrypt((const_DES_cblock *)out, (DES_cblock *)out2, &key_sch, DES_DECRYPT);
    std::cout << out2 << std::endl;

    getchar();
    return 0;
}
