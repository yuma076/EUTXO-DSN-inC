#include "contractVal.h"
#include "crypto.h"
#include <time.h>

// contractValidator(Input) -> 0/1
bool contractValidator(Context *cntxt) {
    char redeemer[MAX_REDEEMER_LEN] = {};
    char *c_contractredeemer;
    strcpy(redeemer, cntxt->inputInfo[cntxt->thisInput].redeemer);
    c_contractredeemer = strtok(redeemer, ",");
    int contractredeemer = atoi(c_contractredeemer);
    bool result = true;
    switch (contractredeemer) {
    case PoRep: {
        // Parse redeemer
        char *c_id, *proofs, *tauDs, *c_N, *challenges, *b64_key, *b64_iv;
        c_id = strtok(NULL, ",");
        proofs = strtok(NULL, ",");
        tauDs = strtok(NULL, ",");
        c_N = strtok(NULL, ",");
        challenges = strtok(NULL, ",");
        b64_key = strtok(NULL, ",");
        b64_iv = strtok(NULL, ",");
        if(c_id == NULL || proofs == NULL || tauDs == NULL || c_N == NULL || challenges == NULL || b64_key == NULL || b64_iv == NULL) {
            result &= false;
            break;
        }
        int id = atoi(c_id);
        int N = atoi(c_N);
        unsigned char *Provider_key = base64_decode(b64_key); // processed free
        unsigned char *Provider_iv = base64_decode(b64_iv); // processed free

        // Verify the proof of Replication.
        int tauD_num = Tree_num_fromleaf(N);
        char *proof[CHALLENGE_NUM] = {};
        proof[0] = strtok(proofs, ":");
        for(int i = 1; i < CHALLENGE_NUM; i++) proof[i] = strtok(NULL, ":");
        char **tauD = (char **)malloc(tauD_num * sizeof(char*)); // processed free
        if (!tauD) {
            printf("Fail to allocate memory.\n");
            exit(EXIT_FAILURE);
        }
        memset(tauD, 0, tauD_num * sizeof(char*));
        tauD[0] = strtok(tauDs, ":");
        for(int i = 1; i < tauD_num; i++) tauD[i] = strtok(NULL, ":");
        char *c_challenge;
        int challenge[CHALLENGE_NUM + 1] = {};
        c_challenge = strtok(challenges, ":");
        challenge[0] = atoi(c_challenge);
        for(int i = 1; i < CHALLENGE_NUM; i++){
            c_challenge = strtok(NULL, ":");
            challenge[i] = atoi(c_challenge);
        }
        result &= PoRep_Verify(id, tauD, challenge, N, proof, Provider_key, Provider_iv);

        free(tauD);
        free(Provider_key);
        free(Provider_iv);
        
        // Verify current clock is in validity Interval.
        struct timespec current;
        clock_gettime(CLOCK_REALTIME, &current);
        if(!(((current.tv_sec > cntxt->validityInterval.start.tv_sec) ||
                (current.tv_sec == cntxt->validityInterval.start.tv_sec && current.tv_nsec > cntxt->validityInterval.start.tv_nsec)) && 
            ((current.tv_sec < cntxt->validityInterval.end.tv_sec) || 
                (current.tv_sec == cntxt->validityInterval.end.tv_sec && current.tv_nsec < cntxt->validityInterval.end.tv_nsec)))) {
                    result &= false;
                    printf("invalid Interval\n");
                    }
        break;
    }
    case Extract: {
        BN_CTX *ctx = BN_CTX_new(); // processed free
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1); // processed free
        BIGNUM *sig_s_hat = BN_new(), *sig_s = BN_new(); // processed free
        char *hex_sig_s_hat, *hex_Y, *hex_sig_s, *hex_p, *hex_a, *hex_b, *hex_n, *hex_h, *hex_G;

        hex_sig_s_hat = strtok(NULL, ",");
        strtok(NULL, ",");
        hex_Y = strtok(NULL, ",");
        hex_sig_s = strtok(NULL, ",");
        hex_p = strtok(NULL, ",");
        hex_a = strtok(NULL, ",");
        hex_b = strtok(NULL, ",");
        hex_n = strtok(NULL, ",");
        hex_h = strtok(NULL, ",");
        hex_G = strtok(NULL, ",");
        if(hex_sig_s_hat == NULL || hex_Y == NULL || hex_sig_s == NULL || hex_p == NULL || 
                hex_a == NULL || hex_b == NULL || hex_n == NULL || hex_h == NULL || hex_G == NULL) {
            result &= false;
            break;
        }
        // set group
        BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new(), *n = BN_new(), *h = BN_new(); // processed free
        EC_POINT *G = EC_POINT_new(group); // processed free
        BN_hex2bn(&p, hex_p);
        BN_hex2bn(&a, hex_a);
        BN_hex2bn(&b, hex_b);
        BN_hex2bn(&n, hex_n);
        BN_hex2bn(&h, hex_h);
        EC_POINT_hex2point(group, hex_G, G, ctx);
        EC_GROUP_set_curve(group, p, a, b, ctx);
        EC_GROUP_set_generator(group, G, n, h);
        BN_free(p); BN_free(a); BN_free(b); BN_free(n); BN_free(h);
        EC_POINT_free(G); 
        // g^s ?= g^s' (= g^s_hat * Y)
        EC_POINT *S_hat = EC_POINT_new(group), *Y = EC_POINT_new(group), *Sd = EC_POINT_new(group), *S = EC_POINT_new(group); // processed free
        BN_hex2bn(&sig_s_hat, hex_sig_s_hat);
        EC_POINT_mul(group, S_hat, sig_s_hat, NULL, NULL, ctx);
        EC_POINT_hex2point(group, hex_Y, Y, ctx);
        EC_POINT_add(group, Sd, S_hat, Y, ctx);
        BN_hex2bn(&sig_s, hex_sig_s);
        EC_POINT_mul(group, S, sig_s, NULL, NULL, ctx);
        result &= (EC_POINT_cmp(group, Sd, S, ctx) == 0);

        BN_CTX_free(ctx);
        BN_free(sig_s_hat); BN_free(sig_s);
        EC_POINT_free(S_hat); EC_POINT_free(Y); EC_POINT_free(Sd); EC_POINT_free(S);
        break;
    }
    case Burnt: {
        printf("Contract is broken and collateral is lost.\n");
        cntxt->outputInfo[cntxt->outputInfo_count].value = cntxt->inputInfo[cntxt->thisInput].value;
        strcpy(cntxt->outputInfo[cntxt->outputInfo_count].ValidatorHash, "Burnt Address");
        strcpy(cntxt->outputInfo[cntxt->outputInfo_count].datumHash, "");
        break;
    }
    default:
        printf("Invalid redeemer\n");
        exit(EXIT_FAILURE);
    }
    if(!result) {
        snprintf(cntxt->inputInfo[cntxt->thisInput].redeemer, 3, "%d%c", Burnt, ',');
        contractValidator(cntxt);
    }
    return true;
}