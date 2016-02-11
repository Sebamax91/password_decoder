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
  unsigned char encryption[32];

  MPI_Init(&argc,&argv);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &world_size);
  gethostname(hostname,255);

  char word[32];

  if (rank == 0) {
    //encrypt passwords
    for(int i=0; i< 10; i=i+1) {
      sha256_encryption(psw[i], encryption);
      memcpy(psw_encrypted[i], encryption, sizeof(encryption));
    }
    //send passwords to slaves
    for (int i = 0; i < (sizeof(psw_encrypted)/ sizeof (char[32])); i++ ) {
      for (int j = 1; j < world_size; j++ ) {
        MPI_Send(&psw_encrypted[i], sizeof (char[32]), MPI_CHAR, j , 0, MPI_COMM_WORLD);
      }
    }
    /*while !notermino{
    //send tag -1 si termino
    //send tag posicion encontrada si encontre
    //llevar array de todos los que ya terminaron para salir del while

    }*/
  } else { //I'm a slave
    for (int h = 0; h < 10; h++ ) {
      //receive passwords to desencrypt
      MPI_Recv(&word, sizeof (char[32]), MPI_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      memcpy(psw_encrypted[h], word, sizeof(word));
    }
    //encryptar y comparar con todas las passwords las partes del archivo que correspondan
    //crear hilo para fuerza bruta
    //si encuentro mando con tag correspondiente
    //si termino mando que termine
      // printf("Process %d received word %s from process 0\n", rank, word);
      // for(int i=0; i< TOTAL_PASSWORDS; i=i+1) {
      //   memset(blk.psw, 0, sizeof(&blk.psw));
      //   sha256_decryption(&blk, &psw_encrypted[i]);
      //   fprintf(stderr, "The password is: %s\n", blk.psw);
      // }
  }
  MPI_Finalize();
  return 0;
}
