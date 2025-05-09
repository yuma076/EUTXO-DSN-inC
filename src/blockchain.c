
#include "blockchain.h"

// partial tx for contract
bool partial_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, const char *receiver_pub, int payment) {
    // inputs
    char *redeemer = (char*)malloc(strlen(sender_priv) + 1); // processed free
    if (!redeemer) {
        printf("Fail to allocate memory.\n");
        return false;
    }
    memset(redeemer, 0, strlen(sender_priv) + 1);
    strcpy(redeemer, sender_priv);
    char input_datum[] = "Holding";
    // outputs
    char output_datum[] = "Holding";

    makeTx((char*)sender_pub, redeemer, input_datum, payment, receiver_pub, output_datum, tx);

    free(redeemer);

    return true;
}

// complete the partial tx for contract
bool complete_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, int collateral) {
    // fill a part of inputs and outputs in Tx.
    // inputs
    char *redeemer = (char*)malloc(strlen(sender_priv) + 1); // processed free
    if (!redeemer) {
        printf("Fail to allocate memory.\n");
        return false;
    }
    strcpy(redeemer, sender_priv);
    char input_datum[] = "Holding";
    // outputs
    char output_datum[] = "Contract";
    
    makeValIn_from_now(tx, 0, 5);

    makeTx((char*)sender_pub, redeemer, input_datum, collateral, "./pem/validator_address.hex", output_datum, tx);

    free(redeemer);

    genTxid(tx, tx->txid);

    if (!verifyTx(tx)) {
        printf("Fail to verify Tx.\n");
        return false;
    }else copyTx(&txpool.txs[txpool.tx_count++], tx);
    if(txpool.tx_count >= MAX_TXS) chainBlock();
    
    return true;
}

bool testTx(int id, char** replica, int N, int collateral, char **tauD, unsigned char *Provider_key, unsigned char *Provider_iv) {
    Tx tx = {0};
    // create redeemer
    char **proof = (char**)malloc(CHALLENGE_NUM * sizeof(char*)); // processed free
    if (!proof) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(proof, 0, CHALLENGE_NUM * sizeof(char*));
    for(int i = 0; i < CHALLENGE_NUM; i++) {
        proof[i] = (char*)malloc(VDE_CT_LEN(BIN_HASH_SIZE) + 1); // processed free
        if (!proof[i]) {
            printf("Fail to allocate memory.\n");
            exit(EXIT_FAILURE);
        }
        memset(proof[i], 0, VDE_CT_LEN(BIN_HASH_SIZE) + 1);
    }
    int challenge[CHALLENGE_NUM] = {};
    PoRep_Poll(N, challenge);
    
#if !defined (MODE_BURNT) || (MODE_BURNT != 0)
#ifdef MODE_REPLICA_COMPRESSION
    PoRep_Prove_malicious(replica, N, id, challenge, proof);
#else
    PoRep_Prove(replica, N, id, challenge, proof);
#endif
#endif

    int tauD_num = Tree_num_fromleaf(N);
    char proofs[CHALLENGE_NUM * (VDE_CT_LEN(BIN_HASH_SIZE) + 1) + 1] = {};
    char *tauDs = (char*)malloc(tauD_num * (HEX_HASH_SIZE + 1) + 1); // processed free
    if (!tauDs) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(tauDs, 0, tauD_num * 65 + 1);
    char *challenges = (char*)malloc(CHALLENGE_NUM * (N + 1) + 1); // processed free
    if (!challenges) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(challenges, 0, CHALLENGE_NUM * (N + 1) + 1);
    
    int i;

#if !defined (MODE_BURNT) || (MODE_BURNT != 0)
    // (str*)proof[]={"s1","s2",...,"sn"} -> (str)proofs="s1:s2:...:sn"
    for(i = 0; i < CHALLENGE_NUM - 1; i++) {
        strcat(proofs, proof[i]);
        strcat(proofs, ":");
    }
    strcat(proofs, proof[i]);
#endif

    // (str*)tauD[]={"o1","o2",...,"on"} -> (str)tauDs="o1:o2:...:on"
    for(i = 0; i < tauD_num - 1; i++) {
        strcat(tauDs, tauD[i]);
        strcat(tauDs, ":");
    }
    strcat(tauDs, tauD[i]);

    // (int*)challenge[]={c1,c2,...,cn} -> (str)challenge="c1:c2:...:cn"
    for(i = 0; i < CHALLENGE_NUM - 1; i++) snprintf(challenges, 3 * (i + 1) + 1,"%s%d%c", challenges, challenge[i], ':');
    snprintf(challenges, (i + 1) * 3,"%s%d", challenges, challenge[i]);

    char *b64_key = base64_encode(Provider_key, AES_KEY_SIZE); // processed free
    char *b64_iv = base64_encode(Provider_iv, AES_BLOCK_SIZE); // processed free

    char *redeemer = (char*)malloc(MAX_REDEEMER_LEN); // processed free
    if (!redeemer) {
        printf("Fail to allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memset(redeemer, 0, MAX_REDEEMER_LEN);
    snprintf(redeemer, MAX_REDEEMER_LEN," %d%c%d%c%s%c%s%c%d%c%s%c%s%c%s", PoRep, ',', id, ',', proofs, ',', tauDs, ',', N, ',', challenges, ',', b64_key, ',', b64_iv);

    for(int i = 0; i < CHALLENGE_NUM; i++) free(proof[i]);
    free(proof);
    free(tauDs);
    free(challenges);
    free(b64_key);
    free(b64_iv);
    
    // Inputs
    char validator[] = "./pem/validator_address.hex";
    char input_datum[] = "Contract";
    // Outputs
    char output_datum[] = "Contract";
#if (MODE_BURNT == 1)
    makeValIn_from_now(&tx, 0, 0);
#else
    makeValIn_from_now(&tx, 0, 5);
#endif
    makeTx(validator, redeemer, input_datum, collateral, "./pem/validator_address.hex", output_datum, &tx);
    free(redeemer);

    genTxid(&tx, tx.txid);

    if (!verifyTx(&tx)) {
        printf("Fail to verify Tx.\n");
        return false;
    } else copyTx(&txpool.txs[txpool.tx_count++], &tx);
    if(txpool.tx_count >= MAX_TXS) chainBlock();

    return true;
}

void partial_finalTx(Tx *tx, BIGNUM *sig_s_hat, BIGNUM *sig_r) {
    // redeemer
    char *hex_sig_s_hat = BN_bn2hex(sig_s_hat); // processed free
    char *hex_sig_r = BN_bn2hex(sig_r); // processed free
    snprintf(tx->inputs[tx->input_count].redeemer, MAX_REDEEMER_LEN,"%d%c%s%c%s", Extract, ',', hex_sig_s_hat, ',', hex_sig_r);

    OPENSSL_free(hex_sig_s_hat); OPENSSL_free(hex_sig_r);
}

bool complete_finalTx(const EC_GROUP *group, Tx *tx, const EC_POINT *AS_pubkey, const EC_POINT *Y, const BIGNUM *K, BN_CTX *ctx, const char *receiver_pub, int collateral) {
    char *hex_sig_s_hat, *hex_sig_r;
    char redeemer[MAX_REDEEMER_LEN] = {};
    strcpy(redeemer, tx->inputs[0].redeemer);
    strtok(redeemer, ",");
    hex_sig_s_hat = strtok(NULL, ",");
    hex_sig_r = strtok(NULL, ",");

    BIGNUM *sig_s_hat = BN_new(), *sig_r = BN_new(), *sig_s = BN_new(); // processed free
    BN_hex2bn(&sig_s_hat, hex_sig_s_hat);
    BN_hex2bn(&sig_r, hex_sig_r);
    if(!AS_pVrf(group, AS_pubkey, sig_s_hat, sig_r, Y, ctx)) {
        printf("Fail to verify the pre-signature.\n");
        return false;
    }
    
    AS_Adapt(group, sig_s_hat, K, ctx, sig_s);

    char *hex_sig_s = BN_bn2hex(sig_s); // processed free
    char *hex_Y = EC_POINT_point2hex(group, Y, POINT_CONVERSION_COMPRESSED, ctx); // processed free

    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new(), *n = BN_new(), *h = BN_new(); // processed free
    EC_POINT *G = EC_POINT_new(group); // processed free
    EC_GROUP_get_curve(group, p, a, b, ctx);
    EC_GROUP_get_order(group, n, ctx);
    EC_GROUP_get_cofactor(group, h, ctx);
    G = (EC_POINT*)EC_GROUP_get0_generator(group);

    char *hex_p, *hex_a, *hex_b, *hex_n, *hex_h, *hex_G;
    hex_p = BN_bn2hex(p); hex_a = BN_bn2hex(a); hex_b = BN_bn2hex(b); hex_n = BN_bn2hex(n); hex_h = BN_bn2hex(h); // processed free
    hex_G = EC_POINT_point2hex(group, G, POINT_CONVERSION_UNCOMPRESSED, ctx); // processed free
    snprintf(tx->inputs[0].redeemer, MAX_REDEEMER_LEN,"%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s", tx->inputs[0].redeemer, ',', hex_Y, ',', hex_sig_s, ',', hex_p, ',', hex_a, ',', hex_b, ',', hex_n, ',', hex_h, ',', hex_G);

    BN_free(sig_s_hat); BN_free(sig_r); BN_free(sig_s);
    OPENSSL_free(hex_sig_s); OPENSSL_free(hex_Y);
    BN_free(p); BN_free(a); BN_free(b); BN_free(n); BN_free(h); 
    EC_POINT_free(G);
    OPENSSL_free(hex_p); OPENSSL_free(hex_a); OPENSSL_free(hex_b); OPENSSL_free(hex_n); OPENSSL_free(hex_h);
    OPENSSL_free(hex_G);

    // Inputs
    // validator
    char validator[] = "./pem/validator_address.hex";
    // datum
    char input_datum[] = "Contract";
    strcpy(redeemer, tx->inputs[0].redeemer);
    // Outputs
    char output_datum[] = "Holding";
    makeValIn_from_now(tx, 0, 5);
    makeTx(validator, redeemer, input_datum, collateral, receiver_pub, output_datum, tx);

    genTxid(tx, tx->txid);

    if (!verifyTx(tx)) {
        printf("Fail to verify Tx.\n");
        return false;
    } else copyTx(&txpool.txs[txpool.tx_count++], tx);
    if(txpool.tx_count >= MAX_TXS) chainBlock();

    return true;
}