#include<stdio.h>

int main(int argc, char** argv) {
  printf("Hello World From %s\n", sizeof(void*) == 4 ? "32-bits" : "64-bits");
  return 0;
}
