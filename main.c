// #include <mysql.h>
// #include <stdio.h>

// main() {
//    fprintf(stderr, "Hello Main\n");
//    MYSQL *conn;
//    MYSQL_RES *res;
//    MYSQL_ROW row;
//    char *server = "localhost";
//    char *user = "root";
//    char *password = "root"; /* set me first */
//    char *database = "mysql";
//    conn = mysql_init(NULL);
//    /* Connect to database */
//    if (!mysql_real_connect(conn, server,
//          user, password, database, 0, NULL, 0)) {
//       fprintf(stderr, "%s\n", mysql_error(conn));
//       exit(1);
//    }
//    /* send SQL query */
//    if (mysql_query(conn, "show tables")) {
//       fprintf(stderr, "%s\n", mysql_error(conn));
//       exit(1);
//    }
//    res = mysql_use_result(conn);
//    /* output table name */
//    printf("MySQL Tables in mysql database:\n");
//    while ((row = mysql_fetch_row(res)) != NULL)
//       printf("%s \n", row[0]);
//    /* close connection */
//    mysql_free_result(res);
//    mysql_close(conn);
// }

#include <mpi.h>
#import <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "encryptor/sha256.h"

const int NUMBER_OF_CHILDS = 2;
pid_t pids[NUMBER_OF_CHILDS];

int main(int argc, char* argv[]) {
  // if (argc == 1) {
  //   fprintf(stderr, "ERROR: No arguments were passed. \n\n");
  // }

  // unsigned char text1[] = {"Sebastian"};
  // sha256_encryption(text1);

  // unsigned char text2[] = {"Sebastian"};
  // sha256_encryption(text2);

  //MPI Parameters
  int rank;
  int world_size;
  char hostname[256];
  //Constant
  int TOTAL_PASSWORDS = 10;

  SHA256_DECRYPTION_BLK blk;

  char psw[10][32] = {
    "me123",
    "zovgott1natt=",
    "sags777",
    "marvinelmarcianito",
    "iunius",
    "dumpischildhood",
    "davus",
    "bumpersrock11588",
    "9T*wwwww",
    "       1234567"
  };

  char psw_encrypted[10][32];
  char psw_found[10][32];
  unsigned char encryption[32];

  MPI_Init(&argc,&argv);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &world_size);
  gethostname(hostname,255);

  char word[32];
  int slaveResponse;
  MPI_Status status;
  bool finished;
  bool slavesFinished[world_size];

  if (rank == 0) {
    //encrypt passwords
    for(int i=0; i< 10; i=i+1) {
      sha256_encryption(psw[i], encryption);
      memcpy(psw_encrypted[i], encryption, sizeof(encryption));
    }
    //send passwords to slaves
    for (int i = 0; i < (sizeof(psw_encrypted)/ sizeof (char[32])); i++ ) {
      for (int j = 1; j < world_size; j++ ) {
        MPI_Send(&psw_encrypted[i], sizeof (char[32]), MPI_CHAR, j , 0, MPI_COMM_WORLD);//Tag 0 = first messages to slaves
      }
    }
    //initialize all slaves as false
    for(int i = 0; i < (world_size - 1); i++){
      slavesFinished[i] = false;
    }
    //initialize all received passwords as ""
    for(int i = 0; i < (world_size - 1); i++){
      psw_found[i] = "";
    }
    /* while not all slaves finished */
    while( !finished ) {
      MPI_Recv(&slaveResponse, 1, MPI_INT, MPI_ANY_SOURCE, 1, MPI_COMM_WORLD, &status);//Tag 1 = slave sends a int
      if (slaveResponse  == -1){
        slavesFinished[(status.MPI_SOURCE - 1)] = true;
        finished = true;
        //iterate slavesFinished to know if all are finished
        for(int i = 0; i < (world_size - 1); i++){
          finished = finished && slavesFinished[i];
        }
      }else { //slave found a password
        MPI_Recv(&word, sizeof (char[32]), MPI_CHAR, status.MPI_SOURCE, 2, MPI_COMM_WORLD, MPI_STATUS_IGNORE);//Tag 2 = slave sends a psw
        memcpy(word, psw_found[slaveResponse], sizeof(word));   
      }
    }
  } else { //I'm a slave
    for (int h = 0; h < 10; h++ ) {
      //receive passwords to desencrypt
      MPI_Recv(&word, sizeof (char[32]), MPI_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      memcpy(psw_encrypted[h], word, sizeof(word));
    }
    //Abrir parte del archivo correspondiente
    pid_t pid;
    for (int i = 0; i < NUMBER_OF_CHILDS; i++) {
        pid = fork();

        if (pid == -1) { 
          // error
          fprintf(stderr, "ERROR: Fork operation could not complete succesfully\n");
          exit(EXIT_FAILURE);
        } else if(pid == 0){ 
          // child
          printf("child %d process number: %d on host %s\n", i , rank, hostname);
          if i == 0 {
            //first child make some logic
          } else {
            //usar palabras del diccionario sin alterar, child 1
            //Tomar una palabra encriptarla y compararla con todo el arreglo
            //Si no da coincidencia avanzar palabra y repetir
            //Si da coincidencia tengo el indice y la palabra sin encriptar
            char password_found[32];
            int index;
            MPI_Send(&index, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);//Tag 1 = first messages to slaves
            MPI_Send(&password_found[i], sizeof (char[32]), MPI_CHAR, 0 , 2, MPI_COMM_WORLD);//Tag 2 = slave sends a psw
            //Al terminar mandar termine
            MPI_Send(-1, 1, MPI_INT, 0 , 1, MPI_COMM_WORLD);//Tag 1 = first messages to slaves
          }
          break;
        } else { 
          // parent
          pids[i] = pid;
        }
    }

    // Finish the execution if i'm child
    if (pid == 0) { return 1; }

    //Parent wait for all the childs to finish their execution.
    for (int i = 0; i < NUMBER_OF_CHILDS; i++) {
      waitpid(pids[i], NULL, 0);
      // fprintf(stderr, "child %d finished process number: %d on host %s\n", pids[i], rank, hostname);
    }
  }
  MPI_Finalize();
  return 0;
}