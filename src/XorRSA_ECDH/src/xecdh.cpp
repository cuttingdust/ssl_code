#include "xecdh.h"

#include <iostream>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>

class XEcdh::PImpl
{
public:
    PImpl(XEcdh *owenr);
    ~PImpl() = default;

public:
    XEcdh    *owenr_ = nullptr;
    int       nid_   = NID_secp256k1; ///  ѡ����Բ����   //NID_sm2
    EVP_PKEY *pkey_  = nullptr;       ///  ��Կ��
};

XEcdh::PImpl::PImpl(XEcdh *owenr) : owenr_(owenr)
{
}

XEcdh::XEcdh()
{
    impl_ = std::make_unique<XEcdh::PImpl>(this);
}

XEcdh::~XEcdh() = default;

auto XEcdh::createKey() -> bool
{
    /// ������Բ���߲�����������
    auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    int  re   = EVP_PKEY_paramgen_init(pctx);
    if (re != 1)
    {
        EVP_PKEY_CTX_free(pctx);
        ERR_print_errors_fp(stderr);
        return false;
    }

    /// ѡ����Բ����
    re = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, impl_->nid_);
    if (re != 1)
    {
        EVP_PKEY_CTX_free(pctx);
        ERR_print_errors_fp(stderr);
        return false;
    }

    /// ����ec�����洢��params
    EVP_PKEY *params = nullptr;
    re               = EVP_PKEY_paramgen(pctx, &params);
    if (re != 1)
    {
        EVP_PKEY_CTX_free(pctx);
        ERR_print_errors_fp(stderr);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    /// ������Բ������Կ��
    /// ����ec����������Կ�Դ���������
    auto kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    /// ��Կ�������ĳ�ʼ��
    re = EVP_PKEY_keygen_init(kctx);
    if (re != 1)
    {
        EVP_PKEY_CTX_free(kctx);
        ERR_print_errors_fp(stderr);
        return false;
    }

    re = EVP_PKEY_keygen(kctx, &impl_->pkey_);
    EVP_PKEY_CTX_free(kctx);
    if (re != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    std::cout << "EVP_PKEY_keygen success!" << std::endl;
    return true;
}

auto XEcdh::getPubKey(unsigned char *pub_key) -> int
{
    if (!impl_->pkey_)
        return 0;

    auto key = EVP_PKEY_get0_EC_KEY(impl_->pkey_);
    auto pub = EC_KEY_get0_public_key(key);

    int re = EC_POINT_point2oct(EC_KEY_get0_group(key),  /// ��Բ����
                                pub,                     /// ��Կ�� kG
                                POINT_CONVERSION_HYBRID, /// ���ݴ�Ÿ�ʽ
                                pub_key,                 /// ����ռ�
                                1024,                    /// ����ռ��ֽ���
                                0                        /// ����������ģ���ѡ
    );
    return re;
}

auto XEcdh::octToPKey(const unsigned char *pub_key, int size) -> EVP_PKEY *
{
    if (!impl_->pkey_)
        return nullptr;

    /// �õ���ǰ��Բ���߲���
    auto key = EVP_PKEY_get0_EC_KEY(impl_->pkey_);

    /// ��ȡ��Բ����
    auto group = EC_KEY_get0_group(key);

    /// pub_key ot EC_POINT
    EC_POINT *p  = EC_POINT_new(group); /// peer��Կ
    int       re = EC_POINT_oct2point(group, p, pub_key, size, NULL);
    if (re != 1)
    {
        EC_POINT_free(p);
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    auto ec = EC_KEY_new();
    re      = EC_KEY_set_group(ec, group);
    if (re != 1)
    {
        EC_POINT_free(p);
        EC_KEY_free(ec);
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    re = EC_KEY_set_public_key(ec, p);
    if (re != 1)
    {
        EC_POINT_free(p);
        EC_KEY_free(ec);
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    EC_POINT_free(p);

    auto peerkey = EVP_PKEY_new();
    re           = EVP_PKEY_set1_EC_KEY(peerkey, ec);
    if (re != 1)
    {
        EC_KEY_free(ec);
        EVP_PKEY_free(peerkey);
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    EC_KEY_free(ec);

    return peerkey;
}

auto XEcdh::compute(unsigned char *out, const unsigned char *peer_key, int key_size) -> int
{
    if (!impl_->pkey_)
        return 0;

    /// �趨�Է���Կ ��Կ��bG  ˽Կ��a    ������Կ��abG
    auto peer = octToPKey(peer_key, key_size);
    if (!peer)
        return 0;

    /// ���㹲����Կ
    auto pctx = EVP_PKEY_CTX_new(impl_->pkey_, NULL);
    int  re   = EVP_PKEY_derive_init(pctx); /// ��ʼ����Կ���� ECDH
    if (re != 1)
    {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peer);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    /// ���öԷ���Կ
    re = EVP_PKEY_derive_set_peer(pctx, peer);
    if (re != 1)
    {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peer);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    /// ���㹲����ԿabG
    size_t outlen = 1024;
    re            = EVP_PKEY_derive(pctx, out, &outlen);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer);
    if (re != 1)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return outlen;
}
