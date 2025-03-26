#include "xsec.h"

#include <openssl/des.h>

class XSec::PImpl
{
public:
    PImpl(XSec *owenr);
    ~PImpl() = default;

public:
    /// \brief DES ECB模式加密
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto enDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int;

    /// \brief DES ECB模式解密
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto deDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int;

    /// \brief DES CBC模式加密
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto enDesCBC(const unsigned char *in, int in_size, unsigned char *out) -> int;

    /// \brief  DES CBC模式解密
    /// \param in
    /// \param in_size
    /// \param out
    /// \return
    auto deDesCBC(const unsigned char *in, int in_size, unsigned char *out) -> int;

public:
    XSec            *owenr_      = nullptr;
    XSecType         type_       = XSecType::XDES_ECB;
    bool             is_en_      = true;
    int              block_size_ = 0;  /// 数据块大小 分组大小
    DES_key_schedule ks_;              /// DES算法秘钥
    unsigned char    iv_[128] = { 0 }; /// 初始化向量
};

XSec::PImpl::PImpl(XSec *owenr) : owenr_(owenr)
{
}

auto XSec::PImpl::enDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int
{
    ///数据填充 PKCS7 Padding
    /*
    假设数据长度需要填充n(n>0)个字节才对齐，那么填充n个字节，每个字节都是n;
    如果数据本身就已经对齐了，则填充一块长度为块大小的数据，每个字节都是块大小。
    */
    unsigned char pad[8]       = { 0 };
    int           padding_size = block_size_ - (in_size % block_size_);
    /// 填入补充的字节大小
    memset(pad, padding_size, sizeof(pad));
    int i = 0;
    for (; i < in_size; i += block_size_)
    {
        /// 最后一块数据，小于block_size_ 需要填充
        if (in_size - i < block_size_)
        {
            /// 填入数据
            memcpy(pad, in + i, in_size - i);
            break;
        }
        DES_ecb_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i), &ks_, DES_ENCRYPT);
    }
    /// 补充 PKCS7结尾
    DES_ecb_encrypt((const_DES_cblock *)pad, (DES_cblock *)(out + i), &ks_, DES_ENCRYPT);
    return in_size + padding_size;
}

auto XSec::PImpl::deDesECB(const unsigned char *in, int in_size, unsigned char *out) -> int
{
    for (int i = 0; i < in_size; i += block_size_)
    {
        DES_ecb_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i), &ks_, DES_DECRYPT);
    }
    /// PKCS7 最后一个字节存储的补充字节数
    return in_size - out[in_size - 1];
}

auto XSec::PImpl::enDesCBC(const unsigned char *in, int in_size, unsigned char *out) -> int
{
    /// 填充的数据 PKCS7 Padding
    unsigned char pad[8]       = { 0 };
    int           padding_size = block_size_ - (in_size % block_size_);
    /// 填入补充的字节大小
    memset(pad, padding_size, sizeof(pad));
    /// block 整数倍大小
    int size1 = in_size - (in_size % block_size_);

    /// ncbc保留iv修改 减去需要补充的数据
    DES_ncbc_encrypt(in, out, size1, &ks_, (DES_cblock *)iv_, DES_ENCRYPT);

    /// PKCS7 Padding
    if (in_size % block_size_ != 0)
    {
        /// 复制剩余的数据
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

    /// 初始化iv_
    memset(impl_->iv_, 0, sizeof(impl_->iv_));

    ///密码策略，超出8字节的丢弃，少的补充0
    const_DES_cblock key      = { 0 }; ///少的补充0
    int              key_size = pass.size();
    /// 超出8字节的丢弃，
    if (key_size > impl_->block_size_)
        key_size = impl_->block_size_;
    /// 少的补充0
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
