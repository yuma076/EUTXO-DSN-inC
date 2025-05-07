#include "crypto.h"
#include "Ledger.h"
#include <time.h>

// calculate Hash of data
void calcHash(const unsigned char *data, int data_len, unsigned char *output) {
    SHA256((unsigned char *)data, data_len, output);
}

void hexToBin(const char *hex, unsigned char *bin) {
    for (int i = 0; i < BIN_HASH_SIZE; i++) sscanf(hex + i * 2, "%2hhx", &bin[i]);
}

void binToHex(const unsigned char *bin, char *hex) {
    for (int i = 0; i < BIN_HASH_SIZE; i++) snprintf(hex + i * 2, 3, "%02x", bin[i]);
    hex[64] = '\0';
}

void printBin_asHex(const unsigned char *hash, int bin_len) {
    for (int i = 0; i < bin_len; i++) printf("%02x", hash[i]);
    printf("\n");
}

// To load address in file. The return value must be free after the function is executed.
char *read_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("Can't open the %s file.\n", filename);
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);  // seek tail
    long filesize = ftell(fp);  // gain file size
    rewind(fp);  // return head
    if(filesize > MAX_DATA_SIZE) {
        printf("filesize is too large.\n");
        exit(EXIT_FAILURE);
    }

    char *file_data = (char *)malloc(filesize + 1);
    if (!file_data) {
        printf("Fail to allocate memory.\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    fread(file_data, 1, filesize, fp);
    file_data[filesize] = '\0';

    fclose(fp);
    return file_data;
}

bool calc_validatorHash(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("Can't open the %s file.\n", filename);
        return false;
    }

    unsigned char buf[4096] = {};
    unsigned int hash_len = 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    size_t bytesRead;
    while ((bytesRead = fread(buf, 1, sizeof(buf), fp)) != 0) {
        EVP_DigestUpdate(mdctx, buf, bytesRead);
    }
    fclose(fp);

    unsigned char hash[BIN_HASH_SIZE] = {};

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    char validator_addr[HEX_HASH_SIZE + 1];
    binToHex(hash, validator_addr);

    fp = fopen("./pem/validator_address.hex", "w");
    if (!fp) {
        printf("Failed opening validator address file.");
        return false;
    }

    fprintf(fp, "%s", validator_addr);
    fclose(fp);

    return true;
}

// The return value must be free after the function is executed.
char *base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    char *b64text = (char *)malloc(bufferPtr->length + 1);
    if (!b64text) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return b64text;
}

// The return value must be free after the function is executed.
unsigned char *base64_decode(const char *input) {
    BIO *bio, *b64;
    int input_length = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(input_length * sizeof(unsigned char));
    if (!buffer) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(buffer, 0, input_length);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, input_length);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_read(bio, buffer, input_length);

    BIO_free_all(bio);
    return buffer;
}

// generate public key and private key as a wallet
void genWallet(char *pubkey_file, char *privkey_file) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        printf("Failed to create EVP_PKEY_CTX.\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        printf("Failed to initialize EC key generation.\n");
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        printf("Failed to generate EC key.\n");
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(pctx);

    FILE *fp = fopen(pubkey_file, "w");
    if (!fp) {
        printf("Failed opening public key file.\n");
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    if (!PEM_write_PUBKEY(fp, pkey)) {
        printf("Failed writing public key.\n");
        fclose(fp);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    fp = fopen(privkey_file, "w");
    if (!fp) {
        printf("Failed opening private key file.\n");
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        printf("Failed writing private key.\n");
        fclose(fp);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    EVP_PKEY_free(pkey);
}

// randomly generate AES 256bit key and IV
void generate_key_iv(unsigned char *key, unsigned char *iv) {
    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_BLOCK_SIZE);
}

// delay encoding by AES.
int VDE_encode(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, char *ciphertext, double delay) {
    if(delay > 0) {
    #ifdef _WIN32
        DWORD milliseconds = (DWORD)(delay * 1000.0);
        Sleep(milliseconds);
    #else
        struct timespec d;
        d.tv_sec = (time_t)delay;
        d.tv_nsec = (long)((delay - (double)d.tv_sec) * 1e9);
        nanosleep(&d, NULL); // delay
    #endif
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create EVP_CIPHER_CTX.\n");
        exit(EXIT_FAILURE);
    }
    int len, ciphertext_len;
    unsigned char *ciphertext_byte = (unsigned char*)malloc((plaintext_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE); // processed free
    if (!ciphertext_byte) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(ciphertext_byte, 0, (plaintext_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext_byte, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext_byte + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    for (int i = 0; i < ciphertext_len; i++) {
        snprintf(ciphertext + (i * 2), 3, "%02x", ciphertext_byte[i]);
    }
    free(ciphertext_byte);
    ciphertext[ciphertext_len * 2] = '\0';
    return ciphertext_len * 2;
}

// immediately decode by AES
int VDE_decode(const char *hex_input, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    // Processing to convert a hex string to a byte string.
    int ciphertext_len = strlen(hex_input) / 2;
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len); // processed free
    if (!ciphertext) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < ciphertext_len; i++) sscanf(hex_input + 2 * i, "%2hhx", &ciphertext[i]);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create context.\n");
        free(ciphertext);
        exit(EXIT_FAILURE);
    }
    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        printf("Decryption failed (padding error?).\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        exit(EXIT_FAILURE);
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return plaintext_len;
}

int Tree_num_fromleaf(int leaf) {
    int Tree_num = 1;
    while (leaf > 1) {
        Tree_num += leaf;
        leaf = (leaf + 1) / 2;
    }
    return Tree_num;
}

// *tauD is a pointer of each openings as hex string.
int merkle_root(char *data, int data_len, char ***tauD) {
    int N = data_len / HEX_HASH_SIZE;
    int tauD_num = Tree_num_fromleaf(N);
    // calculation Hash for each data
    *tauD = (char**)malloc(tauD_num * sizeof(char*)); // processed free
    if (!*tauD) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(*tauD, 0, tauD_num * sizeof(char*));
    for (int i = 0; i < tauD_num; i++) {
        (*tauD)[i] = (char*)malloc(HEX_HASH_SIZE + 1); // processed free
        if (!(*tauD)[i]) {
            printf("Fail to allocate memory.\n");
            exit(EXIT_FAILURE);
        }
        memset((*tauD)[i], 0, HEX_HASH_SIZE + 1);
    }
    for (int i = 0; i < N; i++) {
        unsigned char bin_tauD[BIN_HASH_SIZE] = {}, bin_data[BIN_HASH_SIZE] = {};
        hexToBin(&data[i * HEX_HASH_SIZE], bin_data);
        calcHash(bin_data, BIN_HASH_SIZE, bin_tauD);
        binToHex(bin_tauD, (*tauD)[i]);
    }
    // calculation Merkle root
    merkle_root_calculation(*tauD, N);
    return tauD_num;
}

// Calculate the root of Merkle Tree.
void merkle_root_calculation(char **tauD, int num_hashes) {
    if (num_hashes == 0) return;
    if (num_hashes == 1) return;
    // It replicates last Hash if the number of Hash is odd.
    int new_size = (num_hashes + 1) / 2;
    for (int i = 0; i < new_size; i++) {
        unsigned char combined[BIN_HASH_SIZE * 2] = {}, bin_tauD1[BIN_HASH_SIZE] = {}, bin_tauD2[BIN_HASH_SIZE] = {};

        hexToBin(tauD[2 * i], bin_tauD1);
        if (2 * i + 1 < num_hashes) hexToBin(tauD[2 * i + 1], bin_tauD2);
        else hexToBin(tauD[2 * i], bin_tauD2);

        memcpy(combined, bin_tauD1, BIN_HASH_SIZE);
        memcpy(combined + BIN_HASH_SIZE, bin_tauD2, BIN_HASH_SIZE);

        unsigned char bin_tauD[BIN_HASH_SIZE] = {};
        calcHash(combined, BIN_HASH_SIZE * 2, bin_tauD);
        binToHex(bin_tauD, tauD[i + num_hashes]);
    }
    // Recursively compute routes
    merkle_root_calculation(&tauD[num_hashes], new_size);
    
}