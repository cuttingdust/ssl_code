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
    /// \brief �ͻ��˴���ssl����
    /// \return
    auto connect() -> bool;

    /// \brief
    /// \return
    auto isEmpty() const -> bool;

    /// \brief ����˽���ssl����
    /// \return
    auto accept() const -> bool;

    /// \brief ��ӡͨ��ʹ�õ��㷨
    auto printCipher() const -> void;

    /// \brief ��ӡ�Է�֤����Ϣ
    auto printCert() const -> void;

private:
    class PImpl;
    std::unique_ptr<PImpl> impl_;
};


#endif // XSSL_H
