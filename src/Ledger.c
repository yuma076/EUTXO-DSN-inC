#include "Ledger.h"

Block Ledger[MAX_BLOCKS];
int block_count = 0;
Block txpool;

void makeValIn_from_now(Tx *tx, double seconds) {
#ifdef _WIN32
    QueryPerformanceFrequency(&tx->validityInterval.frequency);

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    tx->validityInterval.start = now;

    LONGLONG offset_counts = (LONGLONG)(seconds * (double)tx->validityInterval.frequency.QuadPart);
    tx->validityInterval.end.QuadPart = tx->validityInterval.start.QuadPart + offset_counts;
#else
    time_t sec = (time_t)seconds;
    long nsec = (long)((seconds - (double)sec) * 1e9);

    clock_gettime(CLOCK_REALTIME, &tx->validityInterval.start);

    tx->validityInterval.end.tv_sec = tx->validityInterval.start.tv_sec + sec;
    tx->validityInterval.end.tv_nsec = tx->validityInterval.start.tv_nsec + nsec;

    if (tx->validityInterval.end.tv_nsec >= 1000000000L) {
        tx->validityInterval.end.tv_sec += tx->validityInterval.end.tv_nsec / 1000000000L;
        tx->validityInterval.end.tv_nsec %= 1000000000L;
    } else if (tx->validityInterval.end.tv_nsec < 0) {
        long sec_decrement = (-(tx->validityInterval.end.tv_nsec) + 999999999L) / 1000000000L;
        tx->validityInterval.end.tv_sec -= sec_decrement;
    }
#endif
}

// look up Tx 
Tx* lookupTx(char* txid){
    for(int i = 0; i < block_count; i++){
        for(int j = 0; j < Ledger[i].tx_count; j++){
            if(strcmp(Ledger[i].txs[j].txid, txid) == 0) return &Ledger[i].txs[j];
        }
    }
    return NULL;
}

// This gathers utxos in the Tx.
int unspentTxOutput(Tx* tx, OutputRef *utxo, const char *validator) {
    int utxo_count = 0;
    if(strcmp(validator, "signVal") == 0) {
        for(int i = 0; i < (tx->output_count); i++){
            BIO *bio = BIO_new_mem_buf((void*)tx->outputs[i].Addr, -1);
            if (!bio) {
                printf("BIO_new_mem_buf failed.\n");
                exit(EXIT_FAILURE);
            }
            EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
            BIO_free(bio);
            
            if(pkey && tx->outputs[i].usp == unspent) {
                strcpy(utxo[utxo_count].txid, tx->txid);
                utxo[utxo_count].index = i;
                utxo_count++;
            }
            EVP_PKEY_free(pkey);
        }
    } else if(strcmp(validator, "contractVal") == 0) {
        char *validator_addr = read_file("./pem/validator_address.hex"); // processed free
        for(int i = 0; i < (tx->output_count); i++){
            if((strcmp(tx->outputs[i].Addr, validator_addr) == 0) && tx->outputs[i].usp == unspent) {
                strcpy(utxo[utxo_count].txid, tx->txid);
                utxo[utxo_count].index = i;
                utxo_count++;
            }
        }
        free(validator_addr);
    }
    return utxo_count;
}

// This gathers utxos in the Ledger.
int unspentOutput(OutputRef *utxo, const char *validator) {
    int utxo_count = 0;
    for(int i = 0; i < block_count; i++){
        for(int j = 0; j < Ledger[i].tx_count; j++){
            utxo_count += unspentTxOutput(&Ledger[i].txs[j], &utxo[utxo_count], validator);
        }
    }
    return utxo_count;
}

// This shows the all Tx's members of the Ledger.
void printLedger(){
    FILE *fp = fopen("./output/Ledger.txt", "w");
    for(int j = 0; j < block_count; j++) {
        for(int k = 0; k < Ledger[j].tx_count; k++) {
            fprintf(fp, "* TxID:\n%s\n", Ledger[j].txs[k].txid);
            if(Ledger[j].txs[k].input_count > 0) for(int i = 0; i < Ledger[j].txs[k].input_count; i++) fprintf(fp, "* Previous TxID %d:\n%s\n", i+1, Ledger[j].txs[k].inputs[i].outputRef.txid);
            for(int i = 0; i < Ledger[j].txs[k].output_count; i++) fprintf(fp, "* Output %d:\nAddress:\n%s\nValue:%d\n", i+1, Ledger[j].txs[k].outputs[i].Addr, Ledger[j].txs[k].outputs[i].value);
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
}

void copyTx(Tx *destination_tx, Tx *source_tx) {
    strcpy(destination_tx->txid, source_tx->txid);

    for(int i = 0; i < source_tx->input_count; i++) {
        strcpy(destination_tx->inputs[i].outputRef.txid, source_tx->inputs[i].outputRef.txid);
        destination_tx->inputs[i].outputRef.index = source_tx->inputs[i].outputRef.index;
        strcpy(destination_tx->inputs[i].validator, source_tx->inputs[i].validator);
        strcpy(destination_tx->inputs[i].datum, source_tx->inputs[i].datum);
        strcpy(destination_tx->inputs[i].redeemer, source_tx->inputs[i].redeemer);
    }
    destination_tx->input_count = source_tx->input_count;
    for(int i = 0; i < source_tx->output_count; i++) {
        destination_tx->outputs[i].value = source_tx->outputs[i].value;
        strcpy(destination_tx->outputs[i].Addr, source_tx->outputs[i].Addr);
        strcpy(destination_tx->outputs[i].datumHash, source_tx->outputs[i].datumHash);
        destination_tx->outputs[i].usp = source_tx->outputs[i].usp;
    }
    destination_tx->output_count = source_tx->output_count;
#ifdef _WIN32
    destination_tx->validityInterval.start.QuadPart = source_tx->validityInterval.start.QuadPart;
    destination_tx->validityInterval.end.QuadPart = source_tx->validityInterval.end.QuadPart;
    destination_tx->validityInterval.frequency.QuadPart = source_tx->validityInterval.frequency.QuadPart;
#else
    destination_tx->validityInterval.start = source_tx->validityInterval.start;
    destination_tx->validityInterval.end = source_tx->validityInterval.end;
#endif
}

// This records the Block in the ledger.
void chainBlock() {
    Ledger[block_count].tx_count = txpool.tx_count;
    for (int i = 0; i < txpool.tx_count; i++) {
        copyTx(&Ledger[block_count].txs[i], &txpool.txs[i]);
        memset(&txpool.txs[i], 0, sizeof(txpool.txs[i]));
    }
    block_count++;
    txpool.tx_count = 0;
}