#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

typedef struct {
  int length;
  char psw[];
} SHA256_DECRYPTION_BLK;

int  sha256_comparisson(unsigned char* sha256_1, unsigned char* sha256_2);
void sha256_print(unsigned char hash[]);
void sha256_encryption(unsigned char *text, unsigned char *encryption);
void sha256_decryption(SHA256_DECRYPTION_BLK *blk, unsigned char* hash);

#endif
