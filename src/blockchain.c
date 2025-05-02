#include "crypto.h"
#include "Ledger.h"
#include "PoRep.h"
#include "AS.h"
#include "Transaction.h"

#define MODE_NORMAL
// #define MODE_BURNT_0 // MODE_BURNT_0/1 -> 0 is the case of delete replica, 1 is the case of invalid interval.

bool partial_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, const char *receiver_pub, int payment);
bool complete_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, int collateral);
bool testTx(int id, char** replica, int N, int collateral, char **tauD, unsigned char *Provider_key, unsigned char *Provider_iv);
void partial_finalTx(Tx *tx, BIGNUM *sig_s_hat, BIGNUM *sig_r);
bool complete_finalTx(const EC_GROUP *group, Tx *tx, const EC_POINT *AS_pubkey, const EC_POINT *Y, const BIGNUM *K, BN_CTX *ctx, const char *receiver_pub, int collateral);

// partial tx for contract
bool partial_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, const char *receiver_pub, int payment) {
    // inputs
    char validator[] = "signVal";
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
    makeTx(sender_pub, validator, redeemer, input_datum, payment, receiver_pub, output_datum, tx);

    free(redeemer);

    return true;
}

// complete the partial tx for contract
bool complete_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, int collateral) {
    // fill a part of inputs and outputs in Tx.
    // inputs
    char validator[] = "signVal";
    char *redeemer = (char*)malloc(strlen(sender_priv) + 1); // processed free
    if (!redeemer) {
        printf("Fail to allocate memory.\n");
        return false;
    }
    strcpy(redeemer, sender_priv);
    char input_datum[] = "Holding";
    // outputs
    char output_datum[] = "Contract";
    makeValIn_from_now(tx, 5);
    makeTx(sender_pub, validator, redeemer, input_datum, collateral, "./pem/validator_address.hex", output_datum, tx);

    free(redeemer);

    genTxid(tx, tx->txid);
    if (!verifyTx(tx)) {
        printf("Fail to verify Tx.\n");
        return false;
    }
    
    copyTx(&txpool.txs[txpool.tx_count++], tx);
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
#ifdef MODE_NORMAL
    PoRep_Prove(replica, N, id, challenge, proof);
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
#ifdef MODE_NORMAL
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
    char validator[] = "contractVal";
    char input_datum[] = "Contract";
    // Outputs
    char output_datum[] = "Contract";
#ifndef MODE_BURNT_1
    makeValIn_from_now(&tx, 5);
#endif
#ifdef MODE_BURNT_1
    makeValIn_from_now(&tx, 0);
#endif
    makeTx("./pem/validator_address.hex", validator, redeemer, input_datum, collateral, "./pem/validator_address.hex", output_datum, &tx);
    free(redeemer);
    genTxid(&tx, tx.txid);
    if (!verifyTx(&tx)) return false;
    
    copyTx(&txpool.txs[txpool.tx_count++], &tx);
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
    char validator[] = "contractVal";
    // datum
    char input_datum[] = "Contract";
    strcpy(redeemer, tx->inputs[0].redeemer);
    // Outputs
    char output_datum[] = "Holding";
    makeValIn_from_now(tx, 5);
    makeTx("./pem/validator_address.hex", validator, redeemer, input_datum, collateral, receiver_pub, output_datum, tx);

    genTxid(tx, tx->txid);
    if (!verifyTx(tx)) return false;
    
    copyTx(&txpool.txs[txpool.tx_count++], tx);
    if(txpool.tx_count >= MAX_TXS) chainBlock();

    return true;
}

int main(int argc, char *argv[]) {
    OpenSSL_add_all_algorithms();
    if(!calc_validatorHash("./src/contractVal.c")) return 1;
    char User_pub[] = "./pem/User_pub.pem", User_priv[] = "./pem/User_priv.pem";
    char Provider_pub[] = "./pem/Provider_pub.pem", Provider_priv[] = "./pem/Provider_priv.pem";

// ----- Setup ------ //
    // User generates the key pair as wallet.
    genWallet(User_pub, User_priv);
    // Provider generates the key pair as wallet.
    genWallet(Provider_pub, Provider_priv);
    // User has 1000.
    if(!payTx(NULL, NULL, "./pem/User_pub.pem", 1000)) return 1;
    // User has 700, Provider has 300.
    if(!payTx("./pem/User_pub.pem", "./pem/User_priv.pem", "./pem/Provider_pub.pem", 300)) return 1;

// ----- Preprocessing phase ----- //
    // User has the original data.
    if (argc < 2) {
        printf("How to use: %s <ファイル名>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    char *original_data = read_file(filename); // processed free
    if(original_data == NULL) return 1;
    // User encodes the deposited data D~ into D.
    char *data = (char*)malloc(MAX_DATA_SIZE); // processed free
    if (!data) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(data, 0, MAX_DATA_SIZE);
    snprintf(data, MAX_DATA_SIZE, "%s", original_data);
    free(original_data);
    int data_len = strlen(data);
    unsigned char User_key[AES_KEY_SIZE], User_iv[AES_BLOCK_SIZE];
    generate_key_iv(User_key, User_iv);
    char *Uencdata = (char*)malloc(VDE_CT_LEN(data_len)); // processed free by realloc
    if (!Uencdata) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(Uencdata, 0, VDE_CT_LEN(data_len));
    int ct_len = VDE_encode((const unsigned char*)data, data_len, User_key, User_iv, Uencdata, 0);
    // Padding the encoded data with zeros to make it a multiple of HEX_HASH_SIZE and it is called D.
    int pct_len = ((ct_len % HEX_HASH_SIZE) == 0) ? ct_len : (ct_len + HEX_HASH_SIZE - ct_len % HEX_HASH_SIZE);
    char *padding_Uencdata = (char*)realloc(Uencdata, pct_len + 1); // processed free
    if(padding_Uencdata == NULL) {
        free(Uencdata);
        return 1;
    }
    if(ct_len < pct_len) memset(padding_Uencdata + ct_len, 0, pct_len - ct_len + 1);
    else if (ct_len > pct_len) {
        printf("Invalid padding length: pct_len < ct_len\n");
        free(padding_Uencdata);
        return 1;
    } else padding_Uencdata[pct_len] = '\0';
    // User generates the tau_D including the commitment and openings from the padding encoded data D.
    char **tauD;
    int tauD_num = merkle_root(padding_Uencdata, pct_len, &tauD);
// ----- Preprocessing phase ----- //

// ----- Delegation phase ----- //
    // User makes the partial Tx which pays 200 to Provider.
    Tx contract_tx = {0};
    if(!partial_contractTx(&contract_tx, "./pem/User_pub.pem", "./pem/User_priv.pem", "./pem/Provider_pub.pem", 200)) return 1;

        // User passes (D, tau_D, partial contractTx) to Provider.
        // User only saves tauD.

    // Provider generates the AES key and iv for VDE.
    unsigned char Provider_key[AES_KEY_SIZE], Provider_iv[AES_BLOCK_SIZE];
    generate_key_iv(Provider_key, Provider_iv);
    // Provider replicates the encoded data D and refers to the replication as R.
    char **replica = (char**)malloc((pct_len / HEX_HASH_SIZE) * sizeof(char*)); // processed free
    if (!replica) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(replica, 0, (pct_len / HEX_HASH_SIZE) * sizeof(char*));
    for(int i = 0; i < (pct_len / HEX_HASH_SIZE); i++) {
        replica[i] = (char*)malloc(VDE_CT_LEN(BIN_HASH_SIZE) + 1); // processed free
        if (!replica[i]) {
            printf("Fail to allocate memory.\n");
            return 1;
        }
        memset(replica[i], 0, VDE_CT_LEN(BIN_HASH_SIZE) + 1);
    }
    int N = PoRep_Replicate(0, tauD, padding_Uencdata, pct_len, Provider_key, Provider_iv, replica);
    // Provider completes the partial contractTx sent by User by depositing 100 as collateral.
    const int collateral = 100;
    //--- contract Tx embeds the contract metadata (i.e., identifier, period, and transaction validity intervals) and delegation outcomes (i.e., data tag and replication auxiliary). ---
    if(!complete_contractTx(&contract_tx, "./pem/Provider_pub.pem", "./pem/Provider_priv.pem", collateral)) return 1;
// ----- Delegation phase ----- //

#ifndef MODE_BURNT_0
// ----- Preservation phase ----- //
    // Provider makes a publicly verifiable proof showing the storage of R and submits Tx embedding it n times.
    int porep_times = 3;
    for(int i = 0; i < porep_times; i++) {
        if(!testTx(0, replica, N, collateral, tauD, Provider_key, Provider_iv)) return 1;
    }
// ----- Preservation phase ----- //
#endif

#ifdef MODE_BURNT_0
// ----- Preservation phase (Case where collateral is Burnt due to proof failure) ----- //
    // Provider makes a publicly verifiable proof showing the storage of R and submits Tx embedding it n times.
    int porep_times = 3;
    for(int i = 0; i < N; i++) free(replica[i]);
    free(replica);
    replica = (char**)malloc((pct_len / HEX_HASH_SIZE) * sizeof(char*)); // processed free
    if (!replica) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(replica, 0, (pct_len / HEX_HASH_SIZE) * sizeof(char*));
    for(int i = 0; i < (pct_len / HEX_HASH_SIZE); i++) {
        replica[i] = (char*)malloc(VDE_CT_LEN(BIN_HASH_SIZE) + 1); // processed free
        if (!replica[i]) {
            printf("Fail to allocate memory.\n");
            return 1;
        }
        memset(replica[i], 0, VDE_CT_LEN(BIN_HASH_SIZE) + 1);
    }
    for(int i = 0; i < porep_times; i++) {
        if(!testTx(0, replica, N, collateral, tauD, Provider_key, Provider_iv)) return 1;

    }
// ----- Preservation phase (Case where collateral is Burnt due to proof failure) ----- //
#endif

// ----- Retrieval phase ----- //
    // Provider extracts the encoded data exD from R by PoRep Extract.
    char *Pext_padding_Uencdata = (char*)malloc(pct_len + 1); // processed free
    if (!Pext_padding_Uencdata) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(Pext_padding_Uencdata, 0 , pct_len + 1);
    PoRep_Extract(0, tauD, replica, N, Provider_key, Provider_iv, Pext_padding_Uencdata);
    // Provider encodes D(extracted_encdata) into D'(Penc_padding_Uencdata).
    char *Penc_padding_Uencdata = (char*)malloc(VDE_CT_LEN(pct_len + 1));  // processed free
    if (!Penc_padding_Uencdata) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(Penc_padding_Uencdata, 0, VDE_CT_LEN(pct_len + 1));
    unsigned char Extract_key[AES_KEY_SIZE], Extract_iv[AES_BLOCK_SIZE];
    generate_key_iv(Extract_key, Extract_iv);

    VDE_encode((const unsigned char*)Pext_padding_Uencdata, pct_len, Extract_key, Extract_iv, Penc_padding_Uencdata, 0);
    unsigned char Extract_keys[AES_KEY_SIZE + AES_BLOCK_SIZE] = {};
    memcpy(Extract_keys, Extract_key, AES_KEY_SIZE);
    memcpy(Extract_keys + AES_KEY_SIZE, Extract_iv, AES_BLOCK_SIZE);
    // Provider generates G and makes the instance Y = g^(Extract keys).
    BN_CTX *ctx = BN_CTX_new(); // processed free
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1); // processed free
    BIGNUM *K = BN_bin2bn(Extract_keys, AES_KEY_SIZE + AES_BLOCK_SIZE, NULL); // processed free
    BIGNUM *q = BN_new(); // processed free
    EC_GROUP_get_order(group, q, ctx);
    if (BN_cmp(K, q) >= 0) {
        printf("AES key size plus iv size is bigger than q.\n");
        BN_free(q);
        return 1;
    }
    BN_free(q);
    EC_POINT *Y = EC_POINT_new(group); // processed free
    EC_POINT_mul(group, Y, K, NULL, NULL, ctx);

        // Provider passes (G, D', Y) to User.

    // User generates Schnorr keys for the Adaptor Signature. (AS_pubkey = g^AS_privkey)
    EC_POINT *AS_pubkey = EC_POINT_new(group); // processed free
    BIGNUM *AS_privkey = BN_new(); // processed free
    BIGNUM *order = BN_new(); // processed free
    EC_GROUP_get_order(group, order, ctx);
    BN_rand_range(AS_privkey, order);
    EC_POINT_mul(group, AS_pubkey, AS_privkey, NULL, NULL, ctx);
    // User makes the pre-signature.
    BIGNUM *sig_s_hat = BN_new(), *sig_r = BN_new(); // processed free
    AS_pSign(group, AS_pubkey, AS_privkey, Y, sig_s_hat, sig_r, ctx);
    // User make the partial Tx from pre-signature sigma_hat=(s_hat,r).
    Tx finalTx = {0};
    partial_finalTx(&finalTx, sig_s_hat, sig_r);

        // User passes (partial finalTx,AS_pubkey) to Provider.

    // Provider verifies the pre-signature sigma_hat in the partial finalTx and issue the complete finalTx with full signature.
    if(!complete_finalTx(group, &finalTx, AS_pubkey, Y, K, ctx, "./pem/Provider_pub.pem", collateral)) return 1;

    // User extracts Extract key from full signature in the complete finalTx.
    BIGNUM *Uext_K = BN_new(); // processed free
    AS_Ext(group, sig_s_hat, &finalTx, ctx, Uext_K);
    unsigned char Uext_Extract_keys[AES_KEY_SIZE + AES_BLOCK_SIZE + 1] = {};
    unsigned char Uext_Extract_key[AES_KEY_SIZE] = {}, Uext_Extract_iv[AES_BLOCK_SIZE] = {};
    BN_bn2bin(Uext_K, Uext_Extract_keys);
    memcpy(Uext_Extract_key, Uext_Extract_keys, AES_KEY_SIZE);
    memcpy(Uext_Extract_iv, Uext_Extract_keys + AES_KEY_SIZE, AES_BLOCK_SIZE);
    char *Uext_padding_Uencdata = (char*)malloc(pct_len + 1); // processed free by realloc
    if (!Uext_padding_Uencdata) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(Uext_padding_Uencdata, 0, pct_len + 1);
    VDE_decode(Penc_padding_Uencdata, Uext_Extract_key, Uext_Extract_iv, (unsigned char*)Uext_padding_Uencdata);
    // User validates the commitment of the extracted data by comparing it to the original commitment.
    char **Uext_tauD;
    int Uext_tauD_num = merkle_root(Uext_padding_Uencdata, pct_len, &Uext_tauD);
    if(!(strcmp(Uext_tauD[Uext_tauD_num - 1], tauD[tauD_num - 1]) == 0)) {
        printf("Extracted data is different from original data.\n");
        return 1;
    }
    // User decodes extracted data by own key.
    char *Uext_Uencdata = (char*)realloc(Uext_padding_Uencdata, ct_len + 1); // processed free
    if(Uext_Uencdata == NULL) return 1;
    Uext_Uencdata[ct_len] = '\0';
    char *Uext_data = (char*)malloc(data_len + 1); // processed free
    if (!Uext_data) {
        printf("Fail to allocate memory.\n");
        return 1;
    }
    memset(Uext_data, 0, data_len + 1);
    VDE_decode(Uext_Uencdata, User_key, User_iv, (unsigned char*)Uext_data);
// ----- Retrieval phase ----- //

    // output extracted data
    FILE *op_data = fopen("./output/Extracted_data.txt", "w");
    fprintf(op_data, "%s", Uext_data);
    fclose(op_data);

    printLedger();

    EC_POINT_free(Y); EC_POINT_free(AS_pubkey);
    BN_free(K); BN_free(AS_privkey); BN_free(order); BN_free(sig_s_hat); BN_free(sig_r); BN_free(Uext_K);
    BN_CTX_free(ctx);
    free(data); free(padding_Uencdata); free(Pext_padding_Uencdata); free(Penc_padding_Uencdata); free(Uext_Uencdata); free(Uext_data);
    for(int i = 0; i < tauD_num; i++) free(tauD[i]);
    free(tauD);
    for(int i = 0; i < N; i++) free(replica[i]);
    free(replica);

    return 0;
}