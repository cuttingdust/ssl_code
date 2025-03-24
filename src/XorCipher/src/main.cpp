#include <iostream>

constexpr auto XOR_BLOCK = 8;

/// \brief  对称加解密数据
/// \param data  输入数据
/// \param data_size  输入数据大小
/// \param out  输出数据
/// \param pass  秘钥
/// \param pass_size  秘钥长度
/// \return  加解密后数据大小
int XorCipher(const unsigned char *data, int data_size, unsigned char *out, const unsigned char *pass, int pass_size)
{
    /// 初始化密钥
    auto p = *(unsigned long long *)pass;

    /// 数据源转换成8字节数据类型
    auto d = (unsigned long long *)data;
    /// 输出数据
    auto o = (unsigned long long *)out;
    /// 数据分组处理
    int i = 0;
    for (; i < data_size / XOR_BLOCK; i++)
    {
        /// XOR 异或运算
        o[i] = (d[i] ^ p);
    }

    int re_size = data_size;
    return re_size;
}

int main(int argc, char *argv[])
{
    unsigned char data[]     = "测试加解密数据TEST";
    unsigned char out[1024]  = { 0 };
    unsigned char out2[1024] = { 0 };

    unsigned char pass[]    = "123456";
    int           pass_size = strlen((char *)pass);
    int           len       = XorCipher(data, sizeof(data), out, pass, pass_size);
    std::cout << len << "|" << out << std::endl;
    len = XorCipher(out, len, out2, pass, pass_size);
    std::cout << len << ":" << out2 << std::endl;

    return 0;
}
