#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/time.h>

extern bool FUZZING_foundCrash;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct timeval t;
  gettimeofday(&t, NULL);
  if (t.tv_usec % 10000 == 0) { return 1; }
  raise(SIGSEGV);
  assert(false);
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
  // if (Size >= 8 && *(uint32_t *)Data == 0xaabbccdd) { abort(); }
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

#ifdef __cplusplus
}
#endif
