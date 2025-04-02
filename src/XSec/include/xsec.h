/**
 * @file   xsec.h
 * @brief  des的加密解密
 *
 * @details   
 *
 * @author 31667
 * @date   2025-03-26
 */

#ifndef XSEC_H
#define XSEC_H

#include <memory>
#include <string>

class XSec
{
public:
    XSec();
    virtual ~XSec();

    enum XSecType
    {
        XDES_ECB,
        XDES_CBC,
        X3DES_ECB,
        X3DES_CBC,
        XAES128_ECB,
        XAES128_CBC,
        XAES192_ECB,
        XAES192_CBC,
        XAES256_ECB,
        XAES256_CBC,
        XSM4_ECB,
        XSM4_CBC
    };

public:
    /// \brief 初始化加密对象，清理之前的数据
    /// \param type 加密类型
    /// \param pass 秘钥，可以是二进制
    /// \param is_en 加密 false解密
    /// \return 是否成功
    virtual auto init(const XSecType &type, const std::string &pass, bool is_en) -> bool;

    /// \brief 加解密数据
    /// \param in 输入数据
    /// \param in_size 数据大小
    /// \param out 输出数据
    /// \param is_end 是否结束
    /// \return 成功返回加解密后数据字节大小，失败返回0
    virtual auto encrypt(const unsigned char *in, int in_size, unsigned char *out, bool is_end = true) -> int;

    /// \brief
    virtual auto close() -> void;

private:
    class PImpl;
    std::unique_ptr<PImpl> impl_;
};


#endif // XSEC_H
