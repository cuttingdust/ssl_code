/**
 * @file   xssl.h
 * @brief  
 *
 * @details   
 *
 * @author 31667
 * @date   2025-04-10
 */

#ifndef XSSL_H
#define XSSL_H

#include <openssl/types.h>
#include <memory>

class XSSL
{
public:
    XSSL();
    virtual ~XSSL();

    using Ptr = std::shared_ptr<XSSL>;
    static XSSL::Ptr create()
    {
        return std::make_shared<XSSL>();
    }

    void set_ssl(SSL* ssl);

public:
    /// \brief 客户端处理ssl握手
    /// \return
    auto connect() -> bool;

    /// \brief
    /// \return
    auto isEmpty() const -> bool;

    /// \brief 服务端接收ssl连接
    /// \return
    auto accept() const -> bool;

    /// \brief 打印通信使用的算法
    auto printCipher() const -> void;

    /// \brief 打印对方证书信息
    auto printCert() const -> void;

private:
    class PImpl;
    std::unique_ptr<PImpl> impl_;
};


#endif // XSSL_H
