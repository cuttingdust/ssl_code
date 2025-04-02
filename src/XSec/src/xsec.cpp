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
    /// \brief DES ECB模式加密
    /// \param in
    /// \param in_size
    /// \param out
    /// \param is_end
    /// \return
    auto enDesECB(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int;

    /// \brief DES ECB模式解密
    /// \param in
    /// \param in_size
    /// \param out
    /// \param is_end
    /// \return
    auto deDesECB(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int;

    /// \brief DES CBC模式加密
    /// \param in
    /// \param in_size
    /// \param out
    /// \param is_end
    /// \return
    auto enDesCBC(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int;

    /// \brief  DES CBC模式解密
    /// \param in
    /// \param in_size
    /// \param out
    /// \param is_end
    /// \return
    auto deDesCBC(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int;

public:
    XSec            *owenr_      = nullptr;
    XSecType         type_       = XSecType::XDES_ECB;
    bool             is_en_      = true;
    int              block_size_ = 0;  /// 数据块大小 分组大小
    void            *ctx_        = 0;  /// 加解密上下文
    DES_key_schedule ks_;              /// DES算法秘钥
    unsigned char    iv_[128] = { 0 }; /// 初始化向量
};

XSec::PImpl::PImpl(XSec *owenr) : owenr_(owenr)
{
}

auto XSec::PImpl::enDesECB(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int
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

    if (!is_end)
        return in_size;

    /// 补充 PKCS7结尾
    DES_ecb_encrypt((const_DES_cblock *)pad, (DES_cblock *)(out + i), &ks_, DES_ENCRYPT);
    return in_size + padding_size;
}

auto XSec::PImpl::deDesECB(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int
{
    for (int i = 0; i < in_size; i += block_size_)
    {
        DES_ecb_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i), &ks_, DES_DECRYPT);
    }
    if (is_end)
        /// PKCS7 最后一个字节存储的补充字节数
        return in_size - out[in_size - 1];
    else
        return in_size;
}

auto XSec::PImpl::enDesCBC(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int
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

    if (!is_end)
        return in_size;

    /// PKCS7 Padding
    if (in_size % block_size_ != 0)
    {
        /// 复制剩余的数据
        memcpy(pad, in + size1, (in_size % block_size_));
    }
    DES_ncbc_encrypt(pad, out + size1, sizeof(pad), &ks_, (DES_cblock *)iv_, DES_ENCRYPT);
    return in_size + padding_size;
}

auto XSec::PImpl::deDesCBC(const unsigned char *in, int in_size, unsigned char *out, bool is_end) -> int
{
    DES_ncbc_encrypt(in, out, in_size, &ks_, (DES_cblock *)iv_, DES_DECRYPT);
    if (!is_end)
        return in_size;

    return in_size - out[in_size - 1];
}

XSec::XSec()
{
    impl_ = std::make_unique<PImpl>(this);
}

XSec::~XSec() = default;

auto XSec::init(const XSecType &type, const std::string &pass, bool is_en) -> bool
{
    this->close();

    impl_->type_  = type;
    impl_->is_en_ = is_en;

    ///密码策略，超出8字节的丢弃，少的补充0
    unsigned char key[32]  = { 0 }; ///少的补充0
    int           key_size = pass.size();

    /// 加解密算法
    const EVP_CIPHER *cipher = 0;

    switch (type)
    {
        case XDES_ECB:
        case XDES_CBC:
            {
                impl_->block_size_ = DES_KEY_SZ;
                /// 密码策略，超出8字节的丢弃，少的补充0
                /// 超出8字节的丢弃，
                key_size = std::min(key_size, impl_->block_size_);
                /// 少的补充0
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
        case XSM4_ECB:
            {
                cipher = EVP_sm4_ecb();
                break;
            }
        case XSM4_CBC:
            {
                cipher = EVP_sm4_cbc();
                break;
            }
        default:
            break;
    }

    if (!cipher)
        return false;

    /// 分组大小
    impl_->block_size_ = EVP_CIPHER_block_size(cipher);

    // /// 初始化iv_
    // memset(impl_->iv_, 0, sizeof(impl_->iv_));

    /// 密钥补充或者丢弃
    key_size = std::min(key_size, EVP_CIPHER_key_length(cipher));
    memcpy(key, pass.data(), key_size);

    /// 加解密上下文
    impl_->ctx_ = EVP_CIPHER_CTX_new();

    /// 初始化上下文
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
            return impl_->enDesECB(in, in_size, out, is_end);
        }
        else
        {
            return impl_->deDesECB(in, in_size, out, is_end);
        }
    }
    else if (impl_->type_ == XDES_CBC)
    {
        if (impl_->is_en_)
        {
            return impl_->enDesCBC(in, in_size, out, is_end);
        }
        else
        {
            return impl_->deDesCBC(in, in_size, out, is_end);
        }
    }

    /// 不是最后一块数据，不填充PKCS7
    if (is_end)
        EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)impl_->ctx_, EVP_PADDING_PKCS7);
    else
        EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX *)impl_->ctx_, 0); /// 关闭自动填充

    int out_len = 0;
    EVP_CipherUpdate((EVP_CIPHER_CTX *)impl_->ctx_, out, &out_len, in, in_size);
    if (out_len <= 0)
        return 0;

    /// 出去填充得到数据
    int out_padding_len = 0;
    EVP_CipherFinal((EVP_CIPHER_CTX *)impl_->ctx_, out + out_len, &out_padding_len);

    return out_len + out_padding_len;
}

auto XSec::close() -> void
{
    /// 初始化iv_
    memset(impl_->iv_, 0, sizeof(impl_->iv_));
    if (impl_->ctx_)
    {
        EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(impl_->ctx_));
        impl_->ctx_ = nullptr;
    }
}
