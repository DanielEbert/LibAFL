#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  /*volatile int a[4] = {};
  if (Size >= 3) {
    if (Data[0] == 'F') {
      if (Data[1] == 'U') {
        if (Data[2] == 'Z') {
          if (Data[3] == 'Z') {
            // sleep(100);
            return a[4];
          }
        }
      }
    }
  }*/
  // if (Size > 100) return a[3];
  if (Size >= 8 && *(uint32_t *)Data == 0xaabbccdd) { abort(); }
  /*FILE *f;
  f = fopen("/tmp/fuzz", "a");
  fprintf(f, "1");
  fclose(f);*/
  return 0;
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
