#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

#define NUMBER_OF_PASSWORDS 1
#define NUMBER_OF_KNOWN_PASSWORDS 14344391
#define NUMBER_OF_PROCESSES 1
#define PASSWORD_ENCRYPTION_LENGTH 64
#define SHA256_DECRYPT_APPEND 0
#define SHA256_DECRYPT_PREPEND 1

typedef struct {
  int length;
  char *psw;
} SHA256_DECRYPTED_PASSWORD_BLK;

typedef struct {
  int psw_found;
  SHA256_DECRYPTED_PASSWORD_BLK passwords_blk[NUMBER_OF_PASSWORDS];
} SHA256_DECRYPTED_PASSWORDS_BLK;

void sha256_string(unsigned char *sha256, unsigned char *sha256_char);
int  sha256_comparisson(unsigned char* sha256_1, unsigned char* sha256_2);
void sha256_print(unsigned char hash[]);
void sha256_encryption(unsigned char *text, unsigned char *encryption);
void sha256_decryption(SHA256_DECRYPTED_PASSWORDS_BLK *blk, unsigned char** hash, int me);

#endif
