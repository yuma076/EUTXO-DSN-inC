#include "Transaction.h"
#include "Ledger.h"
#include "crypto.h"
#include <time.h>

// generate identity of Tx from previous Tx's id and outputs' value and address
void genTxid(Tx *tx, char *txid) {
    char buffer[2048];
    memset(buffer, 0, 2048);
    for (int i = 0; i < tx->input_count; i++) strcat(buffer, tx->inputs[i].outputRef.txid);
    for (int i = 0; i < tx->output_count; i++) {
        char temp[50];
        snprintf(temp, 50, "%d%s", tx->outputs[i].value, tx->outputs[i].Addr);
        strcat(buffer, temp);
    }
    unsigned char bin_txid[BIN_HASH_SIZE] = {};
    calcHash((unsigned char*)buffer, strlen(buffer), bin_txid);
    binToHex(bin_txid, txid);
}

// verify Tx construction
bool verifyTx(Tx *tx){
    if (strcmp(tx->txid, "") == 0) {
        printf("Failed to verify Tx!\n");
        return false;
    }
    return true;
}

// makeTx(senderkeys(pub,priv),validator,redeemer,datum,value,receiver_pub,datumHash) -> Tx
void makeTx(const char *sender_pub, char *validator, char *redeemer, char *input_datum, int value, const char *receiver_pub, char *output_datum, Tx *tx) {
    if(value <= 0) {
        printf("non-positive value.\n");
        exit(EXIT_FAILURE);
    }
    OutputRef utxos[MAX_UTXO];
    // load sender's public key in pem
    char *sender_pub_pem = read_file(sender_pub); // processed free
    // load receiver's public key in pem
    char *receiver_pub_pem = read_file(receiver_pub); // processed free

    unsigned char bin_validatorHash[BIN_HASH_SIZE] = {};
    char validatorHash[HEX_HASH_SIZE + 1] = {};
    calcHash((const unsigned char*)validator, strlen(validator), bin_validatorHash);
    binToHex(bin_validatorHash, validatorHash);
    // Gather UTXOs
    int utxo_count = unspentOutput(utxos, validator);
    if(utxo_count == 0) {
        printf("No UTXO was found for which the validator is %s.\n", validator);
        printLedger();
        exit(EXIT_FAILURE);
    }

    Context cntxt = {0};
    cntxt.validityInterval.start = tx->validityInterval.start;
    cntxt.validityInterval.end = tx->validityInterval.end;
    // make InputInfo of Context
    for (int i = 0; i < utxo_count; i++) {
        Tx *belongTx = lookupTx(utxos[i].txid);
        if(belongTx == NULL) {
            printf("TxID:%s does not exist.\n",utxos[i].txid);
            exit(EXIT_FAILURE);
        }
        Output *indicate_output = &belongTx->outputs[utxos[i].index];
        unsigned char bin_datumHash[BIN_HASH_SIZE] = {};
        calcHash((const unsigned char*)input_datum, strlen(input_datum), bin_datumHash);
        char datumHash[HEX_HASH_SIZE + 1] = {};
        binToHex(bin_datumHash, datumHash);
        if ((strcmp(indicate_output->Addr, sender_pub_pem) == 0) && (strcmp(indicate_output->datumHash, datumHash) == 0)) {
            strcpy(cntxt.inputInfo[cntxt.inputInfo_count].outputRef.txid, utxos[i].txid);
            cntxt.inputInfo[cntxt.inputInfo_count].outputRef.index = utxos[i].index;
            strcpy(cntxt.inputInfo[cntxt.inputInfo_count].ValidatorHash, validatorHash);
            strcpy(cntxt.inputInfo[cntxt.inputInfo_count].datum, input_datum);
            strcpy(cntxt.inputInfo[cntxt.inputInfo_count].redeemer, redeemer);
            cntxt.inputInfo[cntxt.inputInfo_count].value = indicate_output->value;
            cntxt.inputInfo[cntxt.inputInfo_count].usp = &indicate_output->usp;
            cntxt.inputInfo_count++;
        }
    }
    // make OutputInfo of Context
    cntxt.outputInfo[cntxt.outputInfo_count].value = value;
    strcpy(cntxt.outputInfo[cntxt.outputInfo_count].ValidatorHash, receiver_pub_pem);
    unsigned char bin_datumHash[BIN_HASH_SIZE] = {};
    calcHash((const unsigned char*)output_datum, strlen(output_datum), bin_datumHash);
    char datumHash[HEX_HASH_SIZE + 1] = {};
    binToHex(bin_datumHash, datumHash);
    strcpy(cntxt.outputInfo[cntxt.outputInfo_count].datumHash, datumHash);
    // make validityInterval
    cntxt.validityInterval.start = tx->validityInterval.start;
    cntxt.validityInterval.end = tx->validityInterval.end;

    // Validate for each InputInfo of Context.
    int accumulated = 0;
    for(int i = 0; i < cntxt.inputInfo_count; i++) {
        cntxt.thisInput = i;
        if(strcmp(validator, "signVal") == 0) {
            char sign_data[100];
            unsigned char sign_hashdata[BIN_HASH_SIZE];
            snprintf(sign_data, sizeof(sign_data), "%s%d", cntxt.inputInfo[i].outputRef.txid, cntxt.inputInfo[i].outputRef.index);
            calcHash((unsigned char*)sign_data, strlen(sign_data), sign_hashdata);
            unsigned char *signature;
            unsigned int siglen = 0;
            if(!make_signRedeemer(cntxt.inputInfo[i].redeemer, sign_hashdata, &signature, &siglen)) { // processed free
                printf("Failed to sign.\n");
                free(signature);
                exit(EXIT_FAILURE);
            }
            char *b64_sig = base64_encode(signature, siglen); // processed free
            snprintf(cntxt.inputInfo[i].redeemer, MAX_REDEEMER_LEN, "%s%c%s%c%d", sender_pub_pem, ',', b64_sig, ',', siglen);
            free(b64_sig);
            free(signature);
            if(signValidator(&cntxt)) {
                strcpy(tx->inputs[tx->input_count].outputRef.txid, cntxt.inputInfo[i].outputRef.txid);
                tx->inputs[tx->input_count].outputRef.index = cntxt.inputInfo[i].outputRef.index;
                strcpy(tx->inputs[tx->input_count].validator, validator);
                strcpy(tx->inputs[tx->input_count].datum, cntxt.inputInfo[i].datum);
                strcpy(tx->inputs[tx->input_count].redeemer, cntxt.inputInfo[i].redeemer);
                accumulated += cntxt.inputInfo[i].value;
                *cntxt.inputInfo[i].usp = spent;
                tx->input_count++;
            }
        } else if(strcmp(validator, "contractVal") == 0) {
            if(contractValidator(&cntxt)) {
                strcpy(tx->inputs[tx->input_count].outputRef.txid, cntxt.inputInfo[i].outputRef.txid);
                tx->inputs[tx->input_count].outputRef.index = cntxt.inputInfo[i].outputRef.index;
                strcpy(tx->inputs[tx->input_count].validator, validator);
                strcpy(tx->inputs[tx->input_count].datum, cntxt.inputInfo[i].datum);
                strcpy(tx->inputs[tx->input_count].redeemer, cntxt.inputInfo[i].redeemer);
                accumulated += cntxt.inputInfo[i].value;
                *cntxt.inputInfo[i].usp = spent;
                tx->input_count++;
            }
        } else {
            printf("This is an incorrect Validator.\n");
            exit(EXIT_FAILURE);
        }
        
        if (accumulated >= value) break;
    }
    

    if(accumulated < value){
        printf("The balance is not enough.\n");
        return;
    }

    tx->outputs[tx->output_count].value = cntxt.outputInfo[cntxt.outputInfo_count].value;
    strcpy(tx->outputs[tx->output_count].Addr, cntxt.outputInfo[cntxt.outputInfo_count].ValidatorHash);
    strcpy(tx->outputs[tx->output_count].datumHash, cntxt.outputInfo[cntxt.outputInfo_count].datumHash);
    tx->outputs[tx->output_count].usp = unspent;
    tx->output_count++;

    if (accumulated > value) {
        Output *change = &tx->outputs[tx->output_count++];
        change->value = accumulated - value;
        strcpy(change->Addr, sender_pub_pem);
        char change_datum[] = "Holding";
        memset(bin_datumHash, 0, BIN_HASH_SIZE);
        calcHash((const unsigned char*)change_datum, strlen(change_datum), bin_datumHash);
        memset(datumHash, 0, HEX_HASH_SIZE + 1);
        binToHex(bin_datumHash, datumHash);
        strcpy(change->datumHash, datumHash);
        change->usp = unspent;
    }

    free(receiver_pub_pem);
    free(sender_pub_pem);
}

//---- ECDSA Signature Redeemer and Validator -----
// make_signRedeemer(privkey.pem) -> (signature,signature_length)
bool make_signRedeemer(const char *privkey_file, const unsigned char *data, unsigned char **sig, unsigned int *sig_len) {    
    FILE *fp = fopen(privkey_file, "r");
    if (!fp) {
        printf("Failed opening private key file.\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *ec_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ec_key) {
        printf("Failed to load EC private key\n");
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(ec_key);
        return false;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_key) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(ec_key);
        return false;
    }

    if (EVP_DigestSignUpdate(mdctx, data, BIN_HASH_SIZE) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(ec_key);
        return false;
    }

    size_t len = 0;

    if (EVP_DigestSignFinal(mdctx, NULL, &len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(ec_key);
        return false;
    }

    *sig = (unsigned char *)malloc(len);
    if (!*sig) {
        printf("Fail to allocate memory.\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(ec_key);
        return false;
    }

    if (EVP_DigestSignFinal(mdctx, *sig, &len) <= 0) {
        free(*sig);
        *sig = NULL;
        *sig_len = 0;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(ec_key);
        return false;
    }

    *sig_len = (unsigned int)len;

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(ec_key);
    return true;
}

// signValidator(Input) -> 0/1
bool signValidator(Context *cntxt) {
    char sign_data[100];
    unsigned char sign_hashdata[BIN_HASH_SIZE];
    snprintf(sign_data, sizeof(sign_data), "%s%d", cntxt->inputInfo[cntxt->thisInput].outputRef.txid, cntxt->inputInfo[cntxt->thisInput].outputRef.index);
    calcHash((unsigned char*)sign_data, strlen(sign_data), sign_hashdata);

    char *sender_pub_pem, *b64_sig, *csiglen;
    sender_pub_pem = strtok(cntxt->inputInfo[cntxt->thisInput].redeemer, ",");
    b64_sig = strtok(NULL, ",");
    csiglen = strtok(NULL, ",");
    unsigned int siglen = atoi(csiglen);
    unsigned char *signature = base64_decode(b64_sig); // processed free

    BIO *bio = BIO_new_mem_buf(sender_pub_pem, -1);
    if (!bio) return false;
    EVP_PKEY *ec_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(ec_key);
        return false;
    }

    int verify_status = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, ec_key);
    if (verify_status != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(ec_key);
        return false;
    }

    verify_status = EVP_DigestVerify(mdctx, signature, siglen, sign_hashdata, BIN_HASH_SIZE);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(ec_key);
    free(signature);
    
    return verify_status == 1;
}

// issue payment Tx
bool payTx(const char *sender_pub, const char *sender_priv, const char *receiver_pub, int value) {
    Tx tx = {0};
    tx.input_count = 0;
    // load receiver's public key in pem
    char *receiver_pub_pem = read_file(receiver_pub); // processed free
    // generate genesis Tx
    if(sender_pub == NULL && sender_priv == NULL) {
        Output out1 = {value, "", "", unspent};
        strcpy(out1.Addr, receiver_pub_pem);
        char datum_genesis[] = "Holding";
        unsigned char bin_datumHash[BIN_HASH_SIZE] = {};
        calcHash((const unsigned char*)datum_genesis, strlen(datum_genesis), bin_datumHash);
        char datumHash[HEX_HASH_SIZE + 1] = {};
        binToHex(bin_datumHash, datumHash);
        strcpy(out1.datumHash, datumHash);
        tx.outputs[0] = out1;
        tx.output_count = 1;
    } else {
    //generate payment Tx
        // Inputs
        char validator[] = "signVal";
        char *redeemer = (char*)malloc(strlen(sender_priv) + 1);
        if (!redeemer) {
            printf("Fail to allocate memory.\n");
            exit(EXIT_FAILURE);
        }
        memset(redeemer, 0, strlen(sender_priv) + 1);
        strcpy(redeemer, sender_priv);
        char input_datum[] = "Holding";
        // Outputs
        char output_datum[] = "Holding";
        makeTx(sender_pub, validator, redeemer, input_datum, value, receiver_pub, output_datum, &tx);

        free(redeemer);
    }
    free(receiver_pub_pem);

    genTxid(&tx, tx.txid);
    if (!verifyTx(&tx)) return false;

    copyTx(&txpool.txs[txpool.tx_count++], &tx);
    if(txpool.tx_count >= MAX_TXS) chainBlock();
    
    return true;
}