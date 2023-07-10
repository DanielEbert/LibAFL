#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  volatile int a[4] = {};
  if (Size >= 3) {
    if (Data[0] == 'F') {
      if (Data[1] == 'U') {
        if (Data[2] == 'Z') {
          if (Data[3] == 'Z') { return a[4]; }
        }
      }
    }
  }
  // if (Size > 100) return a[3];
  // if (Size >= 8 && *(uint32_t *)Data == 0xaabbccdd) { abort(); }
  return 0;
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
