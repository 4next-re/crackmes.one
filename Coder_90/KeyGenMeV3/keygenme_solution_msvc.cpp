
#include <iostream>

#define ZERO_LOWDWORD(val) ((val) &= ~(int64_t)0xFFFFFFFF)

typedef unsigned long DWORD;

inline uint32_t rol32(uint32_t value, uint32_t count)
{
    count &= 31;
    return (value << count) | (value >> (32 - count));
}

__int64 __fastcall sub_7FF6357B1610(const char* source)
{
    int source_len;                 // eax
    unsigned __int8 source_char;    // r9
    int v4;                         // ecx
    int v5;                         // edx
    int v6;                         // eax
    __int64 v7;                     // r8
    int v8;                         // eax

    source_len = strlen(source);
    source_char = *source;

    if (*source)
    {
        v4 = -source_len;
        v5 = 0xDEADC0DE;
        v6 = 0x55555555;
        v7 = 0;
        do
        {
            if ((source_char & 1) != 0)
                v8 = source_char + rol32(v6, 29) - 0x1A2B3C4D;
            else
                v8 = (source_char ^ rol32(v6, 12)) - 0x6F0FEDCC;

            v5 = (v7 + v5) ^ (v7 + v5 + v4);
            v6 = v5 ^ v8;
            source_char = source[++v7];
        } while (source_char);
    }
    else
    {
        v6 = 0x55555555;
        v5 = 0xDEADC0DE;
        ZERO_LOWDWORD(v7);
    }
    return (255 * (DWORD)v7 * (DWORD)v7) ^ (unsigned int)(v5 + rol32(v6, 29));
}


int main()
{
    std::string username;
    char buffer[64] = {'\0'};

    std::cout << "Name" << ": ";
    std::cin >> username;

    __int64 code = sub_7FF6357B1610(username.c_str());
    
    _itoa_s(code, buffer, 64, 0x10);

    std::cout<<buffer<<std::endl;

    system("pause");
}

