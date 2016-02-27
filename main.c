#include <mpi.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encryptor/sha256.h"
#include "encryptor/sha256_extended.h"
#include "utils/time.h"

typedef struct {
  int rank;
  SHA256_DECRYPTED_PASSWORDS_BLK *blk;
  unsigned char **psw;
} DECRYPTION_BLK;

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

void terminate_childs(int found) {
  // The process 0 is the master, and it does not receive any message, it sends them
  for (int i = 1; i < NUMBER_OF_PROCESSES; i++ ) {
    // Send that all the passwords were found OR
    // That not all the passwords were found and the decryption
    //    threads have finished their execution already.

    // MPI_Ssend block the thread until it is received on the other side.
    MPI_Ssend(&found, 1, MPI_INT, i , 1, MPI_COMM_WORLD);
  }
}

void *listening_MPI(void *arg) {
  int value;
  MPI_Recv(&value, 1, MPI_INT, MPI_ANY_SOURCE, 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  pthread_exit((void *)NULL);
}

void *sha256(void *arg) {
  int finish = -1;
  DECRYPTION_BLK *decryption_blk = arg;

  sha256_decryption(decryption_blk->blk, decryption_blk->psw, decryption_blk->rank);

  // I send to the master process that I've sent him all the passwords
  // that I've found and that I'm finishing my execution now.
  MPI_Send(&finish, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
  pthread_exit((void *)NULL);
}

void *sha256_extended_append(void *arg) {
  int finish = -1;
  DECRYPTION_BLK *decryption_blk = arg;

  sha256_decryption_extended(decryption_blk->blk, decryption_blk->psw, decryption_blk->rank, SHA256_DECRYPT_APPEND);

  // I send to the master process that I've sent him all the passwords
  // that I've found and that I'm finishing my execution now.
  MPI_Send(&finish, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
  pthread_exit((void *)NULL);
}

void *sha256_extended_preprend(void* arg) {
  int finish = -1;
  DECRYPTION_BLK *decryption_blk = arg;

  sha256_decryption_extended(decryption_blk->blk, decryption_blk->psw, decryption_blk->rank, SHA256_DECRYPT_PREPEND);

  // I send to the master process that I've sent him all the passwords
  // that I've found and that I'm finishing my execution now.
  MPI_Send(&finish, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);
  pthread_exit((void *)NULL);
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

  // Serial Parameters
  SHA256_DECRYPTED_PASSWORDS_BLK blk; // Result structure
  char word[PASSWORD_ENCRYPTION_LENGTH];

  // Initialize MPI
  int provided;
  MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &world_size);

  // Check if the number of MPI slave processes actually were more that 2.
  if (world_size < 2 || NUMBER_OF_PROCESSES < 2) {
    fprintf(stderr, "Not enough slave processes created. Finishing execution...\n");
    exit(EXIT_FAILURE);
  }

  // Reserve space in memory for all the passwords results.
  passwords_malloc(&blk);

  if (rank == 0) {
    print_time(0);

    unsigned char **psw = malloc(NUMBER_OF_PASSWORDS * PASSWORD_ENCRYPTION_LENGTH); // Encryptor variables

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

        // In case all the threads_1 (the one which encrypts all that there is in the txt)
        // finishes without finding all the passwords.
        if (blk.psw_found == NUMBER_OF_PASSWORDS) {
          terminate_childs(-1);
        }
      } else { // Slave found a password
        // Receive the password length from the slave with ID = {status,MPI_SOURCE}
        MPI_Recv(&blk.passwords_blk[psw_idx].length, 1, MPI_INT, status.MPI_SOURCE, 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        // Receive the password from the slave with ID = {status,MPI_SOURCE}
        MPI_Recv(&word, blk.passwords_blk[psw_idx].length, MPI_CHAR, status.MPI_SOURCE, 2, MPI_COMM_WORLD, MPI_STATUS_IGNORE); // TAG_2 = Slave sends a psw
        // Copy the result to the passwords structure
        memcpy(blk.passwords_blk[psw_idx].psw, word, blk.passwords_blk[psw_idx].length);
        // Add 1 to the number of found passwords
        blk.psw_found++;

        // // Send the password that was found to the slaves processes, so they can determine
        // // if the execution must end, or they must continue looking for other passwods.
        if (blk.psw_found == NUMBER_OF_PASSWORDS) {
          terminate_childs(NUMBER_OF_PASSWORDS);
          finished = 1;
        }
      }
    }

    print_time(1);
    passwords_print(blk);

    free(psw);

  } else { //I'm a slave
    int finish = -1;

    DECRYPTION_BLK decryption_blk;
    decryption_blk.blk = &blk;
    decryption_blk.psw = malloc(NUMBER_OF_PASSWORDS * PASSWORD_ENCRYPTION_LENGTH);
    decryption_blk.rank = rank;

    for (int idx = 0; idx < NUMBER_OF_PASSWORDS; idx++ ) {
      // Wait for passwords to decrypt.
      MPI_Recv(&word, PASSWORD_ENCRYPTION_LENGTH, MPI_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      memcpy(&decryption_blk.psw[idx*8], word, PASSWORD_ENCRYPTION_LENGTH);
    }

    void *status;
    pthread_attr_t attr;
    pthread_t thread[4];

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_create(&thread[0], &attr, listening_MPI, (void *)0);
    pthread_create(&thread[1], &attr, sha256, (void *)&decryption_blk);
    pthread_create(&thread[2], &attr, sha256_extended_append, (void *)&decryption_blk);
    pthread_create(&thread[3], &attr, sha256_extended_preprend, (void *)&decryption_blk);

    pthread_attr_destroy(&attr);

    // Wait for the response of the main process on wheater all the passwords
    // were found, or the search has finished.
    pthread_join(thread[0], &status);

    // Finish all the other threads (they must have finished already).
    pthread_cancel(thread[1]);
    pthread_cancel(thread[2]);
    pthread_cancel(thread[3]);
  }

  passwords_free(&blk);

  MPI_Finalize();
  return 0;
}

