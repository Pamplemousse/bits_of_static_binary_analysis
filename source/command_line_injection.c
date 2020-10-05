#include <stdio.h>
#include <stdlib.h>


void check(char folder[15]) {
  char command[50] = {};
  sprintf(command, "ls %s", folder);
  system(command);
}

int main(int argc, char *argv[]) {
  check(argv[1]);
  return 0;
}
