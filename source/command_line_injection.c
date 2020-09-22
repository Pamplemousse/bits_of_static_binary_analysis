#include <stdio.h>
#include <stdlib.h>


void check(char id[15]) {
  char command[50] = {};
  sprintf(command, "ls %s", id);
  system(command);
}

int main(int argc, char *argv[]) {
  check(argv[1]);
  return 0;
}
