#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "sha256.h"
#include "sha256_encryptor.h"

void sha256_string(unsigned char *sha256, unsigned char *sha256_char) {
  int idx;
  for (idx=0; idx < 32; idx++)
    sprintf((char *)&sha256_char[idx * 2], "%02x", sha256[idx]);
}

int sha256_comparisson(unsigned char* sha256_1, unsigned char* sha256_2) {
  unsigned char sha256_char[PASSWORD_ENCRYPTION_LENGTH];
  sha256_string(sha256_1, sha256_char);
  return memcmp(sha256_char, sha256_2, sizeof(sha256_char));
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
  sha256_update(&ctx,text,strlen((const char *)text));
  sha256_final(&ctx,hash);

  memcpy(encryption, hash, sizeof(hash));

  //sha256_print(hash);
}

void sha256_decryption(SHA256_DECRYPTED_PASSWORDS_BLK *blk, unsigned char **hash, int me) {
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  unsigned char encrypted_line[32];

  fp = fopen("files/known_passwords.txt", "r");
  if (fp == NULL) {
    fprintf(stderr, "ERROR: File not found or opened.\n");
    exit(EXIT_FAILURE);
  }

  // Advance the number of lines that correspond to the process you are.
  // Example: If you are process number N, then you have to read from the position
  //          ( NUMBER_OF_LINES / NUMBER_OF_PROCESSES - 1 ) * N -1
  int lines_to_process = (NUMBER_OF_PROCESSES == 1)
    ? NUMBER_OF_KNOWN_PASSWORDS
    : (int)ceil(NUMBER_OF_KNOWN_PASSWORDS / (NUMBER_OF_PROCESSES - 1));
  int starting_line = lines_to_process * (me - 1);

  // Advance the cursor on the file to the corresponding line of the process.
  for(int lines = 0; lines < starting_line; lines++) {
    if (getline(&line, &len, fp) == -1) {
      fprintf(stderr, "ERROR: EOF file reached by process %d\n", me);
      exit(EXIT_FAILURE);
    }
  }

  // This is the main block which encrypts the password
  // and compare it with the one given.
  int i;
  int in_hash;
  int read_lines = 0;
  int psw_found;

  while ((blk->psw_found != NUMBER_OF_PASSWORDS) && ((read = getline(&line, &len, fp)) != -1) && (read_lines < lines_to_process)) {
    // Remove '\n' at the end of the line.
    line[strlen(line) - 1] = '\0';

    // Encrypt the given line in the sha256 format.
    sha256_encryption((unsigned char *)line, encrypted_line);

    i = 0;
    in_hash = 0;
    // WHILE the passwords hasn't been found on the array of encryted passwords AND
    // there are passwords to check yet.
    while(!in_hash && i != NUMBER_OF_PASSWORDS) {
      if (sha256_comparisson(encrypted_line, (unsigned char *)&hash[i*8]) == 0) { // They are the same;
        blk->passwords_blk[i].length = read - 1; // Removal of '\n'
        memcpy(blk->passwords_blk[i].psw, line, read);

        in_hash = 1;
        blk->psw_found++;

        // Send which slave process I am.
        MPI_Send(&i, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
        // Send the length of the password I have found.
        MPI_Send(&blk->passwords_blk[i].length, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
        // Send the password.
        MPI_Send(blk->passwords_blk[i].psw, blk->passwords_blk[i].length, MPI_CHAR, 0 , 2, MPI_COMM_WORLD);
      }
      i++;
    }

    read_lines++;
  }

  fclose(fp);
  if (line) { free(line); }
}
