#include <iostream>
#include <openssl/rand.h>
#include <ctime>

int main(int argc, char *argv[])
{
    std::cout << "First openssl code!" << std::endl;
    time_t        t = time(NULL);
    unsigned char buffer[16];
    int           re = RAND_bytes(buffer, sizeof(buffer));
    for (unsigned char i : buffer)
    {
        std::cout << "[" << static_cast<int>(i) << "]";
    }
    std::cin.get();
    return 0;
}
