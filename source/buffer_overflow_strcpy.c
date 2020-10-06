#include <stdio.h>
#include <string.h>


void vulnerable(char *command) {
  char destination[10];
  strcpy(destination, command);
}

int main(int argc, char *argv[]) {
  printf("*** vulnerable ***\n");
  vulnerable(argv[1]);

  return 0;
}
