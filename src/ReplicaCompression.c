#include "ReplicaCompression.h"
#include "PoRep.h"

bool lookupproof(int ch, char* ext_proof) {
    char redeemer[MAX_REDEEMER_LEN] = {};
    for(int i = block_count - 1; i >= 0; i--){
        for(int j = 0; j < Ledger[i].tx_count; j++){
            for(int k = 0; k < Ledger[i].txs[j].input_count; k++) {
                if(strcmp(Ledger[i].txs[j].inputs[k].validator, "contractVal") == 0) {
                    strcpy(redeemer, Ledger[i].txs[j].inputs[k].redeemer);
                    char *proofs, *challenges;
                    strtok(redeemer, ","); strtok(NULL, ",");
                    proofs = strtok(NULL, ",");
                    strtok(NULL, ","); strtok(NULL, ",");
                    challenges = strtok(NULL, ",");

                    char *proof[CHALLENGE_NUM] = {};
                    proof[0] = strtok(proofs, ":");
                    for(int i = 1; i < CHALLENGE_NUM; i++) proof[i] = strtok(NULL, ":");
                    char *c_challenge;
                    int challenge[CHALLENGE_NUM + 1] = {};
                    c_challenge = strtok(challenges, ":");
                    challenge[0] = atoi(c_challenge);
                    for(int i = 1; i < CHALLENGE_NUM; i++){
                        c_challenge = strtok(NULL, ":");
                        challenge[i] = atoi(c_challenge);
                    }
                    for(int h = 0; h < CHALLENGE_NUM; h++) {
                        if(challenge[h] == ch) {
                            strcpy(ext_proof, proof[h]);
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

void PoRep_Prove_malicious(char** replica, int N, int id, int *challenge, char** proof) {
    for(int i = 0; i < CHALLENGE_NUM; i++) {
        if(replica[challenge[i]] == NULL) {
            char *ext_proof = (char*)malloc(VDE_CT_LEN(BIN_HASH_SIZE) + 1); // processed free
            if (!ext_proof) {
                printf("Fail to allocate memory.\n");
                exit(EXIT_FAILURE);
            }
            memset(ext_proof, 0, VDE_CT_LEN(BIN_HASH_SIZE) + 1);
            if(!lookupproof(challenge[i], ext_proof)) {
                printf("Can't find this proof in the Ledger.\n");
                exit(EXIT_FAILURE);
            }
            snprintf(proof[i], VDE_CT_LEN(BIN_HASH_SIZE) + 1, "%s", ext_proof);
        } else snprintf(proof[i], VDE_CT_LEN(BIN_HASH_SIZE) + 1, "%s", replica[challenge[i]]);
    }
    for(int i = 0; i < CHALLENGE_NUM; i++) {
        free(replica[challenge[i]]);
        replica[challenge[i]] = NULL;
    }
}

void PoRep_Extract_malicious(int id, char **tauD, char **replica, int N, const unsigned char *Provider_key, const unsigned char *Provider_iv, char *data) {
    for(int i = 0; i < N; i++) {
        if(replica[i] == NULL) {
            char *ext_replica = (char*)malloc(VDE_CT_LEN(BIN_HASH_SIZE) + 1); // processed free
            if (!ext_replica) {
                printf("Fail to allocate memory.\n");
                exit(EXIT_FAILURE);
            }
            memset(ext_replica, 0, VDE_CT_LEN(BIN_HASH_SIZE) + 1);
            if(!lookupproof(i, ext_replica)) {
                printf("Can't find this proof in the Ledger.\n");
                exit(EXIT_FAILURE);
            }
            replica[i] = (char*)malloc(VDE_CT_LEN(BIN_HASH_SIZE) + 1); // processed free
            if (!replica[i]) {
                printf("Fail to allocate memory.\n");
                exit(EXIT_FAILURE);
            }
            memset(replica[i], 0, VDE_CT_LEN(BIN_HASH_SIZE) + 1);
            snprintf(replica[i], VDE_CT_LEN(BIN_HASH_SIZE) + 1, "%s", ext_replica);
        }
    }
    PoRep_Extract(id, tauD, replica, N, Provider_key, Provider_iv, data);
}