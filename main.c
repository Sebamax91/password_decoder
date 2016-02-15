#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encryptor/sha256.h"

void retrieve_encrypted_passwords(unsigned char ** psw) {
  // File variables
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  int i = 0;

  fp = fopen("files/passwords.txt", "r");
  if (fp == NULL) {
    fprintf(stderr, "Passwords to decypher could not be found. Exiting now...\n");
    exit(EXIT_FAILURE);
  }

  while ((read = getline(&line, &len, fp)) != -1) {
    line[strlen(line) - 1] = '\0';
    memcpy(&psw[i*8], line, 64);
    i++;
  }

  fclose(fp);
}

int main(int argc, char* argv[]) {
  SHA256_DECRYPTED_PASSWORDS_BLK blk; // Result structure

  unsigned char psw[NUMBER_OF_PASSWORDS][64]; // Encryptor variables
  retrieve_encrypted_passwords(psw);

  sha256_decryption(&blk, psw, 1);

  fprintf(stderr, "Passwords encontradas:\n" );
  for(int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++) {
    fprintf(stderr, "%s\n", blk.passwords_blk[idx].psw);
  }

  return 0;
}
