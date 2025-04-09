/**
 * @file   xecdh.h
 * @brief  
 *
 * @details   
 *
 * @author 31667
 * @date   2025-04-08
 */

#ifndef XECDH_H
#define XECDH_H

#include <memory>

#include <openssl/types.h>

class XEcdh
{
public:
    explicit XEcdh();
    virtual ~XEcdh();

public:
    /// \brief 生成椭圆曲线 秘钥对
    /// \return
    auto createKey() -> bool;

    /// \brief 获取公钥
    /// \param pub_key
    /// \return
    auto getPubKey(unsigned char* pub_key) -> int;

    /// \brief 转换密钥格式
    /// \param pub_key
    /// \param size
    /// \return
    auto octToPKey(const unsigned char* pub_key, int size) -> EVP_PKEY*;

    /// \brief 计算共享密钥 abG
    /// \param out
    /// \param peer_key
    /// \param key_size
    /// \return
    auto compute(unsigned char* out, const unsigned char* peer_key, int key_size) -> int;

private:
    class PImpl;
    std::unique_ptr<PImpl> impl_;
};


#endif // XECDH_H
