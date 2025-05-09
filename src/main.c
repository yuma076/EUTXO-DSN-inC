#include "blockchain.h"
#include "crypto.h"

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
    printf("Setup: success\n");
// ----- Setup ------ //

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
    printf("[U]Preprocessing phase: success\n");
// ----- Preprocessing phase ----- //

// ----- Delegation phase ----- //
    // User makes the partial Tx which pays 200 to Provider.
    Tx contract_tx = {0};
    if(!partial_contractTx(&contract_tx, "./pem/User_pub.pem", "./pem/User_priv.pem", "./pem/Provider_pub.pem", 200)) return 1;

        printf("    [U] -- (D,tauD,partial contractTx) --> [P]\n");
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
    // Only one replica was made.
    int N = PoRep_Replicate(0, tauD, padding_Uencdata, pct_len, Provider_key, Provider_iv, replica);
    printf("[P]Replicate the data: success\n");
    // Provider completes the partial contractTx sent by User by depositing 100 as collateral.
    const int collateral = 100;
    //--- contract Tx embeds the contract metadata (i.e., identifier, period, and transaction validity intervals) and delegation outcomes (i.e., data tag and replication auxiliary). ---
    if(!complete_contractTx(&contract_tx, "./pem/Provider_pub.pem", "./pem/Provider_priv.pem", collateral)) return 1;
    printf("[U][P]Delegation phase: success\n");
// ----- Delegation phase ----- //

#if !defined (MODE_BURNT) || (MODE_BURNT != 0)
// ----- Preservation phase ----- //
    // Provider makes a publicly verifiable proof showing the storage of R and submits Tx embedding it n times.
    int porep_times = 15;
    clock_t start = clock();
    for(int i = 0; i < porep_times; i++) {
        if(!testTx(0, replica, N, collateral, tauD, Provider_key, Provider_iv)) return 1;
        int c = 0;
        for(int j = 0; j < N; j++) if(replica[j] != NULL) c += VDE_CT_LEN(BIN_HASH_SIZE);
        printf("[P]Replica size (%d):%6d B\n", i+1, c);
    }
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("[P]Preservation phase: success; %5fs\n", elapsed);
// ----- Preservation phase ----- //
#else
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
    printf("[P]Preservation phase: success (BURNT)\n");
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
#if !defined (MODE_BURNT) || (MODE_BURNT != 0)
#ifdef MODE_REPLICA_COMPRESSION
    PoRep_Extract_malicious(0, tauD, replica, N, Provider_key, Provider_iv, Pext_padding_Uencdata);
#else
    PoRep_Extract(0, tauD, replica, N, Provider_key, Provider_iv, Pext_padding_Uencdata);
#endif
#endif
    // Provider encodes D(Pext_padding_Uencdata) into D'(Penc_padding_Uencdata).
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

        printf("    [P] -- (G,D',Y) --> [U]\n");
        // Provider passes (G, D', Y) to User.

    // User verifies the relation between D' and Y by Oracle.
    AS_Relation_Oracle(group, Penc_padding_Uencdata, Y, ctx, Pext_padding_Uencdata, pct_len, Extract_key, Extract_iv);
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

        printf("    [U] -- (partial finalTx,AS pubkey) --> [P]\n");
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
    printf("[U]Extract the data in AS: success\n");
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
    printf("[U][P]Retrieval phase: success\n");
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