#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "sha256.h"

void password_append_digits(SHA256_DECRYPTED_PASSWORDS_BLK *blk,
                            unsigned char **hash,
                            unsigned char *psw,
                            unsigned char *new_psw,
                            int psw_length) {

  unsigned char *encrypted_psw = malloc(32);
  int i, in_hash;
  // The given password is appended with 2 digits to later encrypt.
  // unsigned char *new_psw = malloc(psw_length + 2);
  memcpy(new_psw, psw, psw_length);
  memcpy(&new_psw[psw_length], "0", 1);
  memcpy(&new_psw[psw_length + 1], "0", 1);

  for (int idx_i = 0; idx_i < 10; idx_i++) {
    for (int idx_j = 0; idx_j < 10; idx_j++) {
      // Encrypt the given line in the sha256 format.
      sha256_encryption(new_psw, encrypted_psw);

      i = 0;
      in_hash = 0;
      // WHILE the passwords hasn't been found on the array of encryted passwords AND
      // there are passwords to check yet.
      while(!in_hash && i != NUMBER_OF_PASSWORDS) {
        if (sha256_comparisson(encrypted_psw, (unsigned char *)&hash[i*8]) == 0) { // They are the same;
          blk->passwords_blk[i].length = psw_length + 2;
          memcpy(blk->passwords_blk[i].psw, new_psw, blk->passwords_blk[i].length);

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

      if (in_hash) { break; }

      new_psw[psw_length + 1] = (char)((int)new_psw[psw_length + 1] + 1);
    }

    // Reset and start over!
    new_psw[psw_length + 1] = '0';
    new_psw[psw_length] = (char)((int)new_psw[psw_length] + 1);
  }

  memset(new_psw, '\0', psw_length + 2);
}

void password_prepend_digits(SHA256_DECRYPTED_PASSWORDS_BLK *blk,
                            unsigned char **hash,
                            unsigned char *psw,
                            unsigned char *new_psw,
                            int psw_length) {

  unsigned char encrypted_psw[32];
  int i, in_hash;
  // The given password is appended with 2 digits to later encrypt.
  // unsigned char *new_psw = malloc(psw_length + 2);
  memcpy(&new_psw[0], "0", 1);
  memcpy(&new_psw[1], "0", 1);
  memcpy(&new_psw[2], psw, psw_length);

  for (int idx_i = 0; idx_i < 10; idx_i++) {
    for (int idx_j = 0; idx_j < 10; idx_j++) {
      // Encrypt the given line in the sha256 format.
      sha256_encryption(new_psw, encrypted_psw);

      i = 0;
      in_hash = 0;
      // WHILE the passwords hasn't been found on the array of encryted passwords AND
      // there are passwords to check yet.
      while(!in_hash && i != NUMBER_OF_PASSWORDS) {
        if (sha256_comparisson(encrypted_psw, (unsigned char *)&hash[i*8]) == 0) { // They are the same;
          blk->passwords_blk[i].length = psw_length + 2;
          memcpy(blk->passwords_blk[i].psw, new_psw, blk->passwords_blk[i].length);

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

      if (in_hash) { break; }

      new_psw[1] = (char)((int)new_psw[1] + 1);
    }

    // Reset and start over!
    new_psw[1] = '0';
    new_psw[0] = (char)((int)new_psw[0] + 1);
  }

  memset(new_psw, '\0', psw_length + 2);
}

void sha256_decryption_extended(SHA256_DECRYPTED_PASSWORDS_BLK *blk, unsigned char **hash, int me, int DECRYPT_CASE) {
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;

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
  int read_lines = 0;
  unsigned char new_line[64];
  while ((blk->psw_found != NUMBER_OF_PASSWORDS) && ((read = getline(&line, &len, fp)) != -1) && (read_lines < lines_to_process)) {
    // Remove '\n' at the end of the line.
    line[strlen(line) - 1] = '\0';

    // Alter the passwords adding two digits at the end, to later encrypt and compare.
    switch(DECRYPT_CASE) {
      case SHA256_DECRYPT_APPEND:
        password_append_digits(blk, hash, (unsigned char *)line, new_line, read - 1);
        break;
      case SHA256_DECRYPT_PREPEND:
        password_prepend_digits(blk, hash, (unsigned char *)line, new_line, read - 1);
        break;
      default:
        fprintf(stderr, "No valid decrypt method was invoked. Finishing now...\n");
        exit(EXIT_FAILURE);
        break;
    }


    read_lines++;
  }

  fclose(fp);
  if (line) { free(line); }
}
