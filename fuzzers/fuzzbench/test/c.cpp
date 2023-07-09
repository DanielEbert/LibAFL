#include <cstdint>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(uint8_t* input, uint32_t inputSize)
{
    if (inputSize > 8)
    {
        int64_t var = *reinterpret_cast<int64_t*>(&input[0]);
        int64_t var2 = *reinterpret_cast<int64_t*>(&input[5]) + 0x5123;
        // std::cout << var << std::endl;
        // std::cout << var2 << std::endl;

        if (var < 1000)
            return 0;

        if (var == var2)
        {
            return 1; // asm("ud2");
        }

        // for (int i = 0; i < 8; i++)
        //     std::cout << i << input[i] << std::endl;
    }
    return 0;
}
