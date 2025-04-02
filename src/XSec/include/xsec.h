/**
 * @file   xsec.h
 * @brief  des�ļ��ܽ���
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
    };

public:
    /// \brief ��ʼ�����ܶ�������֮ǰ������
    /// \param type ��������
    /// \param pass ��Կ�������Ƕ�����
    /// \param is_en ���� false����
    /// \return �Ƿ�ɹ�
    virtual auto init(XSecType type, const std::string &pass, bool is_en) -> bool;

    /// \brief �ӽ�������
    /// \param in ��������
    /// \param in_size ���ݴ�С
    /// \param out �������
    /// \return �ɹ����ؼӽ��ܺ������ֽڴ�С��ʧ�ܷ���0
    virtual auto encrypt(const unsigned char *in, int in_size, unsigned char *out, bool is_end = true) -> int;

    /// \brief
    virtual auto close() -> void;

private:
    class PImpl;
    std::unique_ptr<PImpl> impl_;
};


#endif // XSEC_H
