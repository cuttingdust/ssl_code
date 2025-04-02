#include "xsec.h"

#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <algorithm>
#include <iostream>
#include <ostream>

class XSec::PImpl
{
public:
    PImpl(XSec *owenr);
    ~PImpl() = default;

public:
    /// \brief DES ECBģʽ����
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto enDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int;

    /// \brief DES ECBģʽ����
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto deDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int;

    /// \brief DES CBCģʽ����
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto enDesCBC(const unsigned char *in, int in_size, unsigned char *out) -> int;

    /// \brief  DES CBCģʽ����
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto deDesCBC(const unsigned char *in, int in_size, unsigned char *out) -> int;

public:
    XSec            *owenr_      = nullptr;
    XSecType         type_       = XSecType::XDES_ECB;
    bool             is_en_      = true;
    int              block_size_ = 0;  /// ���ݿ��С �����С
    void            *ctx_        = 0;  /// �ӽ���������
    DES_key_schedule ks_;              /// DES�㷨��Կ
    unsigned char    iv_[128] = { 0 }; /// ��ʼ������
};

XSec::PImpl::PImpl(XSec *owenr) : owenr_(owenr)
{
}

auto XSec::PImpl::enDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int
{
    ///������� PKCS7 Padding
    /*
    �������ݳ�����Ҫ���n(n>0)���ֽڲŶ��룬��ô���n���ֽڣ�ÿ���ֽڶ���n;
    ������ݱ�����Ѿ������ˣ������һ�鳤��Ϊ���С�����ݣ�ÿ���ֽڶ��ǿ��С��
    */
    unsigned char pad[8]       = { 0 };
    int           padding_size = block_size_ - (in_size % block_size_);
    /// ���벹����ֽڴ�С
    memset(pad, padding_size, sizeof(pad));
    int i = 0;
    for (; i < in_size; i += block_size_)
    {
        /// ���һ�����ݣ�С��block_size_ ��Ҫ���
        if (in_size - i < block_size_)
        {
            /// ��������
            memcpy(pad, in + i, in_size - i);
            break;
        }
        DES_ecb_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i), &ks_, DES_ENCRYPT);
    }
    /// ���� PKCS7��β
    DES_ecb_encrypt((const_DES_cblock *)pad, (DES_cblock *)(out + i), &ks_, DES_ENCRYPT);
    return in_size + padding_size;
}

auto XSec::PImpl::deDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int
{
    for (int i = 0; i < in_size; i += block_size_)
    {
        DES_ecb_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i), &ks_, DES_DECRYPT);
    }
    /// PKCS7 ���һ���ֽڴ洢�Ĳ����ֽ���
    return in_size - out[in_size - 1];
}

auto XSec::PImpl::enDesCBC(const unsigned char *in, int in_size, unsigned char *out) -> int
{
    /// �������� PKCS7 Padding
    unsigned char pad[8]       = { 0 };
    int           padding_size = block_size_ - (in_size % block_size_);
    /// ���벹����ֽڴ�С
    memset(pad, padding_size, sizeof(pad));
    /// block ��������С
    int size1 = in_size - (in_size % block_size_);

    /// ncbc����iv�޸� ��ȥ��Ҫ���������
    DES_ncbc_encrypt(in, out, size1, &ks_, (DES_cblock *)iv_, DES_ENCRYPT);

    /// PKCS7 Padding
    if (in_size % block_size_ != 0)
    {
        /// ����ʣ�������
        memcpy(pad, in + size1, (in_size % block_size_));
    }
    DES_ncbc_encrypt(pad, out + size1, sizeof(pad), &ks_, (DES_cblock *)iv_, DES_ENCRYPT);
    return in_size + padding_size;
}

auto XSec::PImpl::deDesCBC(const unsigned char *in, int in_size, unsigned char *out) -> int
{
    DES_ncbc_encrypt(in, out, in_size, &ks_, (DES_cblock *)iv_, DES_DECRYPT);
    return in_size - out[in_size - 1];
}

XSec::XSec()
{
    impl_ = std::make_unique<PImpl>(this);
}

XSec::~XSec() = default;

auto XSec::init(XSecType type, const std::string &pass, bool is_en) -> bool
{
    this->close();

    impl_->type_  = type;
    impl_->is_en_ = is_en;

    ///������ԣ�����8�ֽڵĶ������ٵĲ���0
    unsigned char key[32]  = { 0 }; ///�ٵĲ���0
    int           key_size = pass.size();

    /// �ӽ����㷨
    const EVP_CIPHER *cipher = 0;

    switch (type)
    {
        case XDES_ECB:
        case XDES_CBC:
            {
                impl_->block_size_ = DES_KEY_SZ;
                /// ������ԣ�����8�ֽڵĶ������ٵĲ���0
                /// ����8�ֽڵĶ�����
                key_size = std::min(key_size, impl_->block_size_);
                /// �ٵĲ���0
                memcpy(&key, pass.data(), key_size);
                DES_set_key(reinterpret_cast<const_DES_cblock *>(key), &impl_->ks_);
                return true;
            }
        case X3DES_ECB:
            {
                cipher = EVP_des_ede3_ecb();
                break;
            }
        case X3DES_CBC:
            {
                cipher = EVP_des_ede3_cbc();
                break;
            }
        case XAES128_ECB:
            {
                cipher = EVP_aes_128_ecb();
                break;
            }
        case XAES128_CBC:
            {
                cipher = EVP_aes_128_cbc();
                break;
            }
        case XAES192_ECB:
            {
                cipher = EVP_aes_192_ecb();
                break;
            }
        case XAES192_CBC:
            {
                cipher = EVP_aes_192_cbc();
                break;
            }
        case XAES256_ECB:
            {
                cipher = EVP_aes_256_ecb();
                break;
            }
        case XAES256_CBC:
            {
                cipher = EVP_aes_256_cbc();
                break;
            }
        default:
            break;
    }

    if (!cipher)
        return false;

    /// �����С
    impl_->block_size_ = EVP_CIPHER_block_size(cipher);

    // /// ��ʼ��iv_
    // memset(impl_->iv_, 0, sizeof(impl_->iv_));

    /// ��Կ������߶���
    key_size = std::min(key_size, EVP_CIPHER_key_length(cipher));
    memcpy(key, pass.data(), key_size);

    /// �ӽ���������
    impl_->ctx_ = EVP_CIPHER_CTX_new();

    /// ��ʼ��������
    const int re = EVP_CipherInit(static_cast<EVP_CIPHER_CTX *>(impl_->ctx_), cipher, key, impl_->iv_, impl_->is_en_);
    if (!re)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    std::cout << "EVP_CipherInit success!" << std::endl;

    return true;
}

auto XSec::encrypt(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int
{
    if (impl_->type_ == XDES_ECB)
    {
        if (impl_->is_en_)
        {
            return impl_->enDesECB(in, in_size, out);
        }
        else
        {
            return impl_->deDesECB(in, in_size, out);
        }
    }
    else if (impl_->type_ == XDES_CBC)
    {
        if (impl_->is_en_)
        {
            return impl_->enDesCBC(in, in_size, out);
        }
        else
        {
            return impl_->deDesCBC(in, in_size, out);
        }
    }

    /// �������һ�����ݣ������PKCS7
    if (is_end)
        EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)impl_->ctx_, EVP_PADDING_PKCS7);
    else
        EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)impl_->ctx_, 0); /// �ر��Զ����

    int out_len = 0;
    EVP_CipherUpdate((EVP_CIPHER_CTX *)impl_->ctx_, out, &out_len, in, in_size);
    if (out_len <= 0)
        return 0;

    /// ��ȥ���õ�����
    int out_padding_len = 0;
    EVP_CipherFinal((EVP_CIPHER_CTX *)impl_->ctx_, out + out_len, &out_padding_len);

    return out_len + out_padding_len;
}

auto XSec::close() -> void
{
    /// ��ʼ��iv_
    memset(impl_->iv_, 0, sizeof(impl_->iv_));
    if (impl_->ctx_)
    {
        EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(impl_->ctx_));
        impl_->ctx_ = nullptr;
    }
}
