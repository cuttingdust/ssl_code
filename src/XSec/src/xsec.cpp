#include "xsec.h"

#include <openssl/des.h>

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
    impl_->type_       = type;
    impl_->is_en_      = is_en;
    impl_->block_size_ = DES_KEY_SZ;

    /// ��ʼ��iv_
    memset(impl_->iv_, 0, sizeof(impl_->iv_));

    ///������ԣ�����8�ֽڵĶ������ٵĲ���0
    const_DES_cblock key      = { 0 }; ///�ٵĲ���0
    int              key_size = pass.size();
    /// ����8�ֽڵĶ�����
    if (key_size > impl_->block_size_)
        key_size = impl_->block_size_;
    /// �ٵĲ���0
    memcpy(&key, pass.data(), key_size);

    DES_set_key(&key, &impl_->ks_);
    return true;
}

auto XSec::encrypt(const unsigned char *in, int in_size, unsigned char *out) -> int
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
    return 0;
}
