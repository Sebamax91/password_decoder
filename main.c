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

#import <stdio.h>
#include <stdlib.h>
#include "encryptor/sha256.h"

int main(int argc, char* argv[]) {
  // if (argc == 1) {
  //   fprintf(stderr, "ERROR: No arguments were passed. \n\n");
  // }

  // unsigned char text1[] = {"Sebastian"};
  // sha256_encryption(text1);

  // unsigned char text2[] = {"Sebastian"};
  // sha256_encryption(text2);

  SHA256_DECRYPTION_BLK blk;

  unsigned char psw[] = {"password_5"};
  unsigned char encryption[32];

  sha256_encryption(psw, encryption);

  sha256_decryption(&blk, encryption);

  fprintf(stderr, "The password is: %s\n", blk.psw);

  return 0;
}
