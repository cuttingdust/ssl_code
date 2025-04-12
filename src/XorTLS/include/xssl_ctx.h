/**
 * @file   xssl_ctx.h
 * @brief  
 *
 * @details   
 *
 * @author 31667
 * @date   2025-04-10
 */

#ifndef XSSL_CTX_H
#define XSSL_CTX_H

#include "xssl.h"
#include <memory>

class XSSL_CTX
{
public:
    XSSL_CTX();
    virtual ~XSSL_CTX();

public:
    /// \brief ��ʼ�������
    /// \param crt_file �����֤���ļ�
    /// \param key_file �����˽Կ�ļ�
    /// \param ca_file ��֤�ͻ���֤�飨��ѡ��
    /// \return ��ʼ���Ƿ�ɹ�
    virtual auto initServer(const char *crt_file, const char *key_file, const char *ca_file = 0) -> bool;

    /// \brief ��ʼ��SSL�ͻ���
    /// \param ca_file  ��֤�����֤��
    /// \return
    virtual auto initClient(const char *ca_file = 0) -> bool;

    /// \brief ����SSLͨ�Ŷ���socket��ssl_st��Դ�ɵ������ͷ�
    /// ����ʧ�ܷ���ͨ��XSSL::isEmpty()�ж�
    /// \param socket
    /// \return
    auto createXSSL(int socket) -> XSSL::Ptr;

    /// \brief �ͷ���Դ
    auto close() -> void;

private:
    class PImpl;
    std::unique_ptr<PImpl> impl_;
};


#endif // XSSL_CTX_H
