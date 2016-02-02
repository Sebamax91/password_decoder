#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"
#include "sha256_encryptor.h"

int sha256_comparisson(unsigned char* sha256_1, unsigned char* sha256_2) {
  return memcmp(sha256_1, sha256_2, sizeof(sha256_1));
}

void sha256_print(unsigned char hash[])
{
  int idx;
  for (idx=0; idx < 32; idx++)
    printf("%02x",hash[idx]);
  printf("\n");
}

void sha256_encryption(unsigned char *text, unsigned char *encryption)
{
  unsigned char hash[32];

  int idx;
  SHA256_CTX ctx;

  sha256_init(&ctx);
  sha256_update(&ctx,text,strlen(text));
  sha256_final(&ctx,hash);

  memcpy(encryption, hash, sizeof(hash));

  // sha256_print(hash);
}

void sha256_decryption(SHA256_DECRYPTION_BLK *blk, unsigned char* hash) {
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  int found = 0;
  unsigned char encrypted_line[32];

  fp = fopen("files/test_passwords.txt", "r");
  if (fp == NULL) {
    fprintf(stderr, "File not found or opened.\n");
    exit(EXIT_FAILURE);
  }

  // This is the main block which encrypts the password
  // and compare it with the one given.
  while ((!found) && ((read = getline(&line, &len, fp)) != -1)) {

    // memcpy(encrypted_line, line, sizeof(line));
    line[strlen(line) - 1] = '\0';
    sha256_encryption(line, encrypted_line);

    if (sha256_comparisson(hash, encrypted_line) == 0) { // They are the same;
      blk->length = read;
      memcpy(blk->psw, line, strlen(line));
      found = 1;
    }

    // printf("%s", line);
  }

  fclose(fp);
  if (line) { free(line); }
}
