#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
  // Check the number of slave processed configured to run.
  // If the number is below 2, the execution must finish, becuase:
  // The first process is the master, which listen to the slaves messages.
  // There are no slave processes searching for a solution.
  if (NUMBER_OF_PROCESSES < 2) {
    fprintf(stderr, "Number of slave processes to create to low. Finishing execution...\n");
    exit(EXIT_FAILURE);
  }

  //MPI Parameters
  pid_t pids[NUMBER_OF_PROCESSES];
  int rank;
  int world_size;

  char word[PASSWORD_ENCRYPTION_LENGTH];

  // Initialize MPI
  MPI_Init(&argc,&argv);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &world_size);

  // Check if the number of MPI slave processes actually were more that 2.
  if (world_size < 2 || NUMBER_OF_PROCESSES < 2) {
    fprintf(stderr, "Not enough slave processes created. Finishing execution...\n");
    exit(EXIT_FAILURE);
  }

  // Serial Parameters
  SHA256_DECRYPTED_PASSWORDS_BLK blk; // Result structure
  unsigned char **psw = malloc(NUMBER_OF_PASSWORDS * PASSWORD_ENCRYPTION_LENGTH); // Encryptor variables

  // Reserve space in memory for all the passwords results.
  passwords_malloc(&blk);

  if (rank == 0) {
    print_time(0);

    MPI_Status status;
    int slaves_finished[NUMBER_OF_PROCESSES - 1] = { 0 };
    int psw_idx, finished;

    // Get all the passwords from the source, in this case, a .txt file and
    // store them in the password array.
    // This task is only done by the main process, since it is going to send
    // them to all the other sub-processes.
    retrieve_encrypted_passwords(psw);

    // Send ALL passwords to slaves.
    for (int i = 0; i < NUMBER_OF_PASSWORDS; i++ ) {
      for (int j = 1; j < world_size; j++ ) {
        // TAG_0 = First messages to slaves
        MPI_Send(&psw[i*8], PASSWORD_ENCRYPTION_LENGTH, MPI_CHAR, j , 0, MPI_COMM_WORLD);
      }
    }

    finished = 0;
    while (!finished) {
      // Wait for the index of the password that is going to be passed.
      // If the index is below 0, that is recognized as the slave process
      // has finished sending all the passwords he had found.
      MPI_Recv(&psw_idx, 1, MPI_INT, MPI_ANY_SOURCE, 1, MPI_COMM_WORLD, &status); // TAG_1 = First messages to slaves

      if (psw_idx  == -1){
        slaves_finished[(status.MPI_SOURCE - 1)] = 1;

        finished = 1;
        for (int i = 0; i < (world_size - 1); i++) {
          // Iterate slaves_finished[] to know if there are all done
          // to terminate the execution of the program.
          finished = finished && slaves_finished[i];
        }
      } else { // Slave found a password
        // Receive the password length from the slave with ID = {status,MPI_SOURCE}
        MPI_Recv(&blk.passwords_blk[psw_idx].length, 1, MPI_INT, status.MPI_SOURCE, 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        // Receive the password from the slave with ID = {status,MPI_SOURCE}
        MPI_Recv(&word, blk.passwords_blk[psw_idx].length, MPI_CHAR, status.MPI_SOURCE, 2, MPI_COMM_WORLD, MPI_STATUS_IGNORE); // TAG_2 = Slave sends a psw
        // Copy the result to the passwords structure
        memcpy(blk.passwords_blk[psw_idx].psw, word, blk.passwords_blk[psw_idx].length);

        // Send the password that was found to the slaves processes, so they can determine
        // if the execution must end, or they must continue looking for other passwods.

        fprintf(stderr, "%s\n", "dadfasd");
        for (int i = 0; i < NUMBER_OF_PASSWORDS; i++ ) {
          MPI_Send(&i, 1, MPI_INT, i , 0, MPI_COMM_WORLD);
          fprintf(stderr, "sent %d\n", i);
        }
      }
    }

    print_time(1);
    passwords_print(blk);

  } else { //I'm a slave
    int finish = -1;
    for (int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++ ) {
      // Wait for passwords to decrypt.
      MPI_Recv(&word, PASSWORD_ENCRYPTION_LENGTH, MPI_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      memcpy(&psw[idx*8], word, PASSWORD_ENCRYPTION_LENGTH);
    }

    for (int fork_idx = 0; fork_idx < 2; fork_idx++) {
      pid_t pid = fork();

      if (pid == -1) { // Error forking.
        fprintf(stderr, "ERROR: Fork operation could not complete succesfully\n");
        exit(EXIT_FAILURE);
      } else if(pid == 0){ // I am a child thread.
        if (fork_idx == 0) {
          // This thread is going to wait for incomming passwords that
          // other processes have decrypthed.
          int psw_idx;
          fprintf(stderr, "child process number: %d - %d\n" , rank, fork_idx);
          // MPI_Recv(&psw_idx, 1, MPI_INT, MPI_ANY_SOURCE, 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE); // TAG_1 = First messages to slaves
          // fprintf(stderr, "%d - %d\n", rank, psw_idx);
          pid_t pid_2 = fork();
          if (pid_2 == -1) { // Error forking.
            fprintf(stderr, "ERROR: Fork operation could not complete succesfully\n");
            exit(EXIT_FAILURE);
          } else if( pid_2 == 0 ){
            fprintf(stderr, "child process of child number: %d\n" , rank);
            MPI_Recv(&psw_idx, 1, MPI_INT, MPI_ANY_SOURCE, 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE); // TAG_1 = First messages to slaves
            fprintf(stderr, "%d - %d\n", rank, psw_idx);
            return 1;
          } else {
            //waitpid(pid_2, NULL, 0);
            // return 1;
          }

        } else {
          fprintf(stderr, "child process number: %d - %d\n" , rank, fork_idx);
          // Decrypt all the passwords possible with this process!!
          sha256_decryption(&blk, psw, rank);
          passwords_print(blk);
          sha256_decryption_extended(&blk, psw, rank, SHA256_DECRYPT_APPEND);
          passwords_print(blk);
          sha256_decryption_extended(&blk, psw, rank, SHA256_DECRYPT_PREPEND);
          passwords_print(blk);

          // Send all the passwords that I've found to the master.
          for (int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++) {
            if (blk.passwords_blk[idx].length != -1) { // A password was found in that position.
              // Send which slave process I am.
              MPI_Send(&idx, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
              // Send the length of the password I have found.
              MPI_Send(&blk.passwords_blk[idx].length, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
              // Send the password.
              MPI_Send(blk.passwords_blk[idx].psw, blk.passwords_blk[idx].length, MPI_CHAR, 0 , 2, MPI_COMM_WORLD);
            }
          }

          // I send to the master process that I've sent him all the passwords
          // that I've found and that I'm finishing my execution now.
          MPI_Send(&finish, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
        }

      } else {
        // parent
        pids[fork_idx] = pid;
        waitpid(pids[fork_idx], NULL, 0);
        fprintf(stderr, "%s\n", "Ended!");
      }
    }

    // Decrypt all the passwords possible with this process!!
    // sha256_decryption(&blk, psw, rank);
    // passwords_print(blk);
    // sha256_decryption_extended(&blk, psw, rank, SHA256_DECRYPT_APPEND);
    // passwords_print(blk);
    // sha256_decryption_extended(&blk, psw, rank, SHA256_DECRYPT_PREPEND);
    // passwords_print(blk);

    // Send all the passwords that I've found to the master.
    // for (int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++) {
    //   if (blk.passwords_blk[idx].length != -1) { // A password was found in that position.
    //     // Send which slave process I am.
    //     MPI_Send(&idx, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
    //     // Send the length of the password I have found.
    //     MPI_Send(&blk.passwords_blk[idx].length, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
    //     // Send the password.
    //     MPI_Send(blk.passwords_blk[idx].psw, blk.passwords_blk[idx].length, MPI_CHAR, 0 , 2, MPI_COMM_WORLD);
    //   }
    // }

    // I send to the master process that I've sent him all the passwords
    // that I've found and that I'm finishing my execution now.
    // MPI_Send(&finish, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
  }

  passwords_free(&blk);
  free(psw);

  MPI_Finalize();
  return 0;
}

