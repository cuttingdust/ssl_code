#include <algorithm>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <iostream>
#include <fstream>

bool EncryptFile(const std::string &passwd, const std::string &in_filename, const std::string &out_filename,
                 bool is_enc)
{
    /// ѡ��ӽ����㷨����������滻
    auto cipher = EVP_des_ede3_cbc();

    /// �����ļ���С
    int in_file_size = 0;

    /// ����ļ���С
    int           out_file_size = 0;
    std::ifstream ifs(in_filename, std::ios::binary); /// �����ƴ������ļ�
    if (!ifs)
        return false;
    std::ofstream ofs(out_filename, std::ios::binary); /// �����ƴ�С����ļ�
    if (!ofs)
    {
        ifs.close();
        return false;
    }
    auto ctx = EVP_CIPHER_CTX_new(); /// �ӽ���������

    /// ��Կ��ʼ�� ����Ķ���
    unsigned char key[128] = { 0 };
    int           key_size = EVP_CIPHER_key_length(cipher); /// ��ȡ��Կ����
    key_size               = std::min<std::basic_string<char>::size_type>(key_size, passwd.size());
    memcpy(key, passwd.data(), key_size);

    unsigned char iv[128] = { 0 }; /// ��ʼ������
    int           re      = EVP_CipherInit(ctx, cipher, key, iv, is_enc);
    if (!re)
    {
        ERR_print_errors_fp(stderr);
        ifs.close();
        ofs.close();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    unsigned char buf[1024] = { 0 };
    unsigned char out[1024] = { 0 };
    int           out_len   = 0;
    /// 1 ���ļ�=��2 �ӽ����ļ�=��3д���ļ�
    while (!ifs.eof())
    {
        /// 1 ���ļ�
        ifs.read((char *)buf, sizeof(buf));
        int count = ifs.gcount();
        if (count <= 0)
            break;
        in_file_size += count; /// ͳ�ƶ�ȡ�ļ���С
        /// 2 �ӽ����ļ� ���ܵ�out
        EVP_CipherUpdate(ctx, out, &out_len, buf, count);
        if (out_len <= 0)
            break;
        /// 3 д���ļ�
        ofs.write((char *)out, out_len);
        out_file_size += out_len;
    }
    /// ȡ�����һ������
    EVP_CipherFinal(ctx, out, &out_len);
    if (out_len > 0)
    {
        ofs.write((char *)out, out_len);
        out_file_size += out_len;
    }

    ifs.close();
    ofs.close();
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "in_file_size:" << in_file_size << std::endl;
    std::cout << "out_file_size:" << out_file_size << std::endl;
    return true;
}


int main(int argc, char *argv[])
{
    {
        auto assert_file  = R"(.\assert\main.cpp)";
        auto encrypt_file = R"(.\assert\main.encrypt.txt)";
        auto decrypt_file = R"(.\assert\main.decrypt.txt)";

        /// �����ļ�
        EncryptFile("12345678", assert_file, encrypt_file, true);

        /// �����ļ�
        EncryptFile("12345678", encrypt_file, decrypt_file, false);

        getchar();
    }


    const unsigned char data[] = "1234567812345"; /// ����
    // const unsigned char data[]    = "1234567812345678"; /// ����
    int data_size = strlen((char *)data);
    std::cout << "data_size = " << data_size << std::endl;
    unsigned char out[1024] = { 0 };                  /// ���
    unsigned char key[128]  = "12345678901234567890"; /// ��Կ
    unsigned char iv[128]   = { 0 };                  /// ��ʼ������

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

    /// Ĭ�� PKCS7 �����С EVP_PADDING_PKCS7
    /// �ر��Զ����
    // EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    int out_size = 0;

    /// ֻ��������С�õ�����,���ȡ���Զ���䣬�������ݶ���
    /// ����Զ���䣬����EVP_CipherFinal �л�ȡ����
    EVP_CipherUpdate(ctx,
                     out,       /// ���
                     &out_size, /// ������ݴ�С
                     data,      /// ��������
                     data_size);
    std::cout << "EVP_CipherUpdate size:" << out_size << std::endl;

    /// ȡ�����һ�����ݣ���Ҫ���ģ���������padding���������
    int padding_size = 0;
    EVP_CipherFinal(ctx, out + out_size, &padding_size);
    std::cout << "padding_size = " << padding_size << std::endl;
    out_size += padding_size;
    std::cout << out_size << ":" << out << std::endl;

    //////////////////////////////////////////////////////////////////
    /// �������� ʹ��ԭ����ctx
    re = EVP_CipherInit(ctx, cipher, key, iv,
                        0 /// 0��ʾ����
    );
    if (!re)
    {
        ERR_print_errors_fp(stderr);
    }

    /// ��������ݻᱻ������ ���ǲ�ȫ������Ҫһ��
    // EVP_CIPHER_CTX_set_padding(ctx, 0);

    /// �������ĺ��ŵ�����
    unsigned char out2[1024] = { 0 };
    int           out2_size  = 0;
    /// �������� �������ȡ����
    EVP_CipherUpdate(ctx, out2, &out2_size, /// ������������
                     out, out_size);        /// ������ܺ�����
    std::cout << "EVP_CipherUpdate out2_size = " << out2_size << std::endl;

    /// ȡ���������
    EVP_CipherFinal(ctx, out2 + out2_size, &padding_size);
    std::cout << "EVP_CipherFinal padding_size=" << padding_size << std::endl;
    out2_size += padding_size;
    std::cout << out2_size << ":" << out2 << "|" << std::endl;

    /// �ͷ�������
    EVP_CIPHER_CTX_free(ctx);

    getchar();
    return 0;
}
