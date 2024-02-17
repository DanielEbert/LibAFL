#include <cstdint>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(uint8_t* input, uint32_t input_size)
{
    if (input_size > 8)
    {
		// __asm__("movl $0, %eax\n\t"
        //    "movl $0, (%eax)");
    }

    return 0;
}
