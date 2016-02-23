#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encryptor/sha256.h"
#include "encryptor/sha256_extended.h"
#include "utils/time.h"

void passwords_print(SHA256_DECRYPTED_PASSWORDS_BLK blk) {
  for (int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++) {
    fprintf(stderr, "password_%d => '%s' - length: %d'\n", idx + 1, (blk.passwords_blk[idx].length > -1) ? blk.passwords_blk[idx].psw : "not found", blk.passwords_blk[idx].length);
  }
}

void passwords_free(SHA256_DECRYPTED_PASSWORDS_BLK *blk) {
  for(int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++) {
    free(blk->passwords_blk[idx].psw);
  }
}

void passwords_malloc(SHA256_DECRYPTED_PASSWORDS_BLK *blk) {
  blk->psw_found = 0;
  for (int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++) {
    blk->passwords_blk[idx].length = -1;
    blk->passwords_blk[idx].psw = (char*)malloc(PASSWORD_ENCRYPTION_LENGTH);
  }
}

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

  while (((read = getline(&line, &len, fp)) != -1) && (i < NUMBER_OF_PASSWORDS)) {
    line[strlen(line) - 1] = '\0';
    memcpy(&psw[i*8], line, PASSWORD_ENCRYPTION_LENGTH);
    i++;
  }

  fclose(fp);
}

int main(int argc, char* argv[]) {
  SHA256_DECRYPTED_PASSWORDS_BLK blk; // Result structure
  unsigned char **psw = malloc(NUMBER_OF_PASSWORDS * PASSWORD_ENCRYPTION_LENGTH); // Encryptor variables

  passwords_malloc(&blk);
  print_time(0);
  retrieve_encrypted_passwords(psw);

  sha256_decryption(&blk, psw, 1);
  sha256_decryption_extended(&blk, psw, 1, SHA256_DECRYPT_APPEND);
  sha256_decryption_extended(&blk, psw, 1, SHA256_DECRYPT_PREPEND);

  print_time(1);
  passwords_print(blk);
  passwords_free(&blk);

  free(psw);

  return 0;
}
