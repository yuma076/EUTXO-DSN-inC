#include "PoRep.h"

// PoRep.Replicate(id,tau,D,key,iv) -> [replica]R
int PoRep_Replicate(int id, char** tauD, char* data, int data_len, const unsigned char *key, const unsigned char *iv, char** replica) {
    int N = data_len / HEX_HASH_SIZE;
    int tauD_num = Tree_num_fromleaf(N);
    double delay = 0.1; // set delay
    printf("Wait %.1lf seconds to make Replication...\n", N * delay);
    for(int i = 0; i < N; i++){
        printf("\r%.0lf seconds elapsed...", (i + 1) * delay);
        fflush(stdout);
        char ids[129] = {};
        snprintf(ids, 129, "%d%s%d", id, tauD[tauD_num - 1], i);
        unsigned char hash_ids[BIN_HASH_SIZE] = {};
        calcHash((unsigned char*)ids, strlen(ids), hash_ids);

        unsigned char result[BIN_HASH_SIZE] = {};
        unsigned int bin_data[BIN_HASH_SIZE] = {};
        for (int j = 0; j < BIN_HASH_SIZE; j++) {
            sscanf(data + (i * HEX_HASH_SIZE) + (j * 2), "%2x", &bin_data[j]);
            result[j] = bin_data[j] ^ hash_ids[j];
        }
        VDE_encode(result, BIN_HASH_SIZE, key, iv, replica[i], delay);
    }
    printf("\n");
    return N;
}

// PoRep.Poll(N) -> [challenge]r = (r1, ... ,rl)
void PoRep_Poll(int N, int *challenge) {
    OutputRef utxos[MAX_UTXO];
    int utxo_count = unspentOutput(utxos, "contractVal");
    if(utxo_count == 0) {
        printf("There are no UTXOs!\n");
        printLedger();
        exit(EXIT_FAILURE);
    } else if(utxo_count > 1) {
        printf("Another contract is underway.\n");
        exit(EXIT_FAILURE);
    }
    char utxos_txid[65];
    strcpy(utxos_txid, utxos[0].txid);
    for (int i = 0; i < CHALLENGE_NUM; i++) {
        utxos_txid[63] = (char)i;
        unsigned char bin_utxo_hash[BIN_HASH_SIZE] = {};
        calcHash((unsigned char*)utxos_txid, strlen(utxos_txid), bin_utxo_hash);
        challenge[i] = ((bin_utxo_hash[1] << 16) | (bin_utxo_hash[2] << 8) | bin_utxo_hash[3]) % N;
    }
}

// PoRep.Prove(R,N,id,r) -> [proof]pi
void PoRep_Prove(char** replica, int N, int id, int *challenge, char** proof) {
    for(int i = 0; i < CHALLENGE_NUM; i++) snprintf(proof[i], VDE_CT_LEN(BIN_HASH_SIZE) + 1, "%s", replica[challenge[i]]);
}

// Verify_Oracle(d,r,tauD) -> 0/1
bool PoRep_Verify_Oracle(char *d, int challenge, char **tauD, int N) {
    int height = (int)log2(N) + 2;
    char **openingfor_d = (char **)malloc((height + 1) * sizeof(char*)); // processed free
    if (!openingfor_d) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(openingfor_d, 0, (height + 1) * sizeof(char*));
    for(int i = 0; i < height; i++) {
        openingfor_d[i] = (char *)malloc(HEX_HASH_SIZE + 1); // processed free
        if (!openingfor_d[i]) {
            printf("Fail to allocate memory.\n");
            exit(EXIT_FAILURE);
        }
        memset(openingfor_d[i], 0, HEX_HASH_SIZE + 1);
    }
    int level = 0, offset = 0, leaf_num = N , ch = challenge;
    while (leaf_num > 1) {
        int sibling_index;
        if (ch % 2 == 0) {
            if (ch == leaf_num - 1) sibling_index = ch;
            else sibling_index = ch + 1;
        } else sibling_index = ch - 1;
        strncpy(openingfor_d[level], tauD[offset + sibling_index], 65);
        offset += leaf_num;
        ch /= 2;
        leaf_num = (leaf_num + 1) / 2;
        level++;
    }

    int opening_d_num = level;

    unsigned char bin_hash_d[BIN_HASH_SIZE] = {}, bin_d[BIN_HASH_SIZE] = {};
    hexToBin(d, bin_d);
    calcHash(bin_d, BIN_HASH_SIZE, bin_hash_d);

    for(int i = 0; i < opening_d_num; i++) {
        unsigned char combined[BIN_HASH_SIZE * 2] = {}, bin_openingfor_d[BIN_HASH_SIZE] = {};
        hexToBin(openingfor_d[i], bin_openingfor_d);
        if (challenge % 2 == 0) {
            memcpy(combined, bin_hash_d, BIN_HASH_SIZE);
            memcpy(combined + BIN_HASH_SIZE, bin_openingfor_d, BIN_HASH_SIZE);
        } else {
            memcpy(combined, bin_openingfor_d, BIN_HASH_SIZE);
            memcpy(combined + BIN_HASH_SIZE, bin_hash_d, BIN_HASH_SIZE);
        }
        calcHash(combined, BIN_HASH_SIZE * 2, bin_hash_d);
        challenge /= 2;
    }
    char root[HEX_HASH_SIZE + 1] = {};
    binToHex(bin_hash_d, root);
    
    for(int i = 0; i < height; i++) free(openingfor_d[i]);
    free(openingfor_d);
    
    int tauD_num = Tree_num_fromleaf(N);
    if(!(strcmp(tauD[tauD_num - 1], root) == 0)) return false;
    return true;
}

// PoRep.Verify(id,tau,r,N,pi) -> 0/1
bool PoRep_Verify(int id, char **tauD, int *challenge, int N, char** proof, const unsigned char *Provider_key, const unsigned char *Provider_iv) {
    bool b = true;
    int tauD_num = Tree_num_fromleaf(N);
    for(int i = 0; i < CHALLENGE_NUM; i++) {
        char ids[129] = {0};
        snprintf(ids, 129, "%d%s%d", id, tauD[tauD_num - 1], challenge[i]);
        unsigned char hash_ids[BIN_HASH_SIZE] = {};
        calcHash((unsigned char*)ids, strlen(ids), hash_ids);

        unsigned char decrypted[BIN_HASH_SIZE] = {};
        VDE_decode(proof[i], Provider_key, Provider_iv, decrypted);
        char d[HEX_HASH_SIZE + 1];
        unsigned int bin_d[BIN_HASH_SIZE] = {};
        for (int j = 0; j < BIN_HASH_SIZE; j++) {
            bin_d[j] = decrypted[j] ^ hash_ids[j];
            snprintf(d + (j * 2), 3, "%02x", bin_d[j]);
        }
        d[HEX_HASH_SIZE] = '\0';

        b &= PoRep_Verify_Oracle(d, challenge[i], tauD, N);
    }
    return b;
}

// PoRep.Extract(id,tau,R,N) -> D
void PoRep_Extract(int id, char **tauD, char **replica, int N, const unsigned char *Provider_key, const unsigned char *Provider_iv, char *data) {
    int tauD_num = Tree_num_fromleaf(N);
    for(int i = 0; i < N; i++) {
        char ids[129] = {};
        snprintf(ids, 129, "%d%s%d", id, tauD[tauD_num - 1], i);
        unsigned char hash_ids[BIN_HASH_SIZE] = {};
        calcHash((unsigned char*)ids, strlen(ids), hash_ids);

        unsigned char decrypted[BIN_HASH_SIZE] = {};
        VDE_decode(replica[i], Provider_key, Provider_iv, decrypted);

        for (int j = 0; j < BIN_HASH_SIZE; j++) {
            unsigned int bin_d;
            bin_d = decrypted[j] ^ hash_ids[j];
            snprintf(data + (i * HEX_HASH_SIZE) + (j * 2), 3, "%02x", bin_d);
        }
    }
    data[N * HEX_HASH_SIZE] = '\0';
    char **exttauD;
    int exttauD_num = merkle_root(data, strlen(data), &exttauD); // processed free
    if(strcmp(tauD[tauD_num - 1], exttauD[exttauD_num - 1]) == 0) {
        printf("[P]Extract the data in PoRep: success\n");
    } else {
        printf("Fail to extract the data in PoRep.");
        for(int i = 0; i < exttauD_num; i++) free(exttauD[i]);
        free(exttauD);
        exit(EXIT_FAILURE);
    }
    for(int i = 0; i < exttauD_num; i++) free(exttauD[i]);
    free(exttauD);
}