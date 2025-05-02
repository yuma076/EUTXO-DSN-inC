#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

#define DEBUG {printf("DEBUG\n");exit(EXIT_FAILURE);}
#define H printf("DEBUG1\n");
#define D printf("DEBUG2\n");

#define AES_KEY_SIZE 32  // 256-bit AES
#define AES_BLOCK_SIZE 16
#define BIN_HASH_SIZE  32
#define HEX_HASH_SIZE 64
#define VDE_CT_LEN(p) (((p) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE * AES_BLOCK_SIZE * 2 + 1)

void calcHash(const unsigned char *data, int data_len, unsigned char *output);
void hexToBin(const char *hex, unsigned char *bin);
void binToHex(const unsigned char *bin, char *hex);
char *read_file(const char *filename);
bool calc_validatorHash(const char *filename);
char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input);
void genWallet(char *pubkey_file, char *privkey_file);
void generate_key_iv(unsigned char *key, unsigned char *iv);
int VDE_encode(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, char *ciphertext, double delay);
int VDE_decode(const char *hex_input, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);
int Tree_num_fromleaf(int leaf);
int merkle_root(char *data, int data_len, char ***tauD);
void merkle_root_calculation(char **tauD, int num_hashes);

#endif // CRYPTO_H
