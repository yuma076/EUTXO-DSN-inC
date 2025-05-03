#ifndef LEDGER_H
#define LEDGER_H

#ifdef _WIN32
    #include <windows.h>
#else
    #include <time.h>
    #include <unistd.h>
#endif

#include "crypto.h"

#define MAX_INPUTS 10
#define MAX_OUTPUTS 10
#define MAX_TXS 1
#define MAX_BLOCKS 100
#define MAX_UTXO 100
#define MAX_DATA_SIZE 2048

#define CHALLENGE_NUM 10

#define MAX_REDEEMER_LEN 10+CHALLENGE_NUM*(VDE_CT_LEN(64)+1)+64+(2*VDE_CT_LEN(MAX_DATA_SIZE/BIN_HASH_SIZE)*65+1)+10+CHALLENGE_NUM*(VDE_CT_LEN(MAX_DATA_SIZE/BIN_HASH_SIZE)+1)*10+64*2+7


typedef enum enmdat{
    Holding,
    Contract
} Datum;

typedef enum enmcontractred{
    PoRep,
    Burnt,
    Extract
} contractRedeemer;

typedef enum enmspnt{
    spent,
    unspent
} Unspent;

typedef struct{
    char txid[HEX_HASH_SIZE + 1];
    int index;
} OutputRef;

typedef struct {
    int value;
    char Addr[513];
    char datumHash[HEX_HASH_SIZE + 1];
    Unspent usp;
} Output;

typedef struct {
    OutputRef outputRef;
    char validator[513];
    char datum[513];
    char redeemer[MAX_REDEEMER_LEN];
} Input;

typedef struct {
    #ifdef _WIN32
        LARGE_INTEGER start;
        LARGE_INTEGER end;
        LARGE_INTEGER frequency;
    #else
        struct timespec start;
        struct timespec end;
    #endif
} Interval;

typedef struct {
    char txid[HEX_HASH_SIZE + 1];
    Input inputs[MAX_INPUTS];
    int input_count;
    Output outputs[MAX_OUTPUTS];
    int output_count;
    Interval validityInterval;
} Tx;

typedef struct {
    Tx txs[MAX_TXS];
    int tx_count;
} Block;

typedef struct {
    int value;
    char ValidatorHash[513];
    char datumHash[HEX_HASH_SIZE + 1];
} OutputInfo;

typedef struct {
    OutputRef outputRef;
    char ValidatorHash[HEX_HASH_SIZE + 1];
    char datum[513];
    char redeemer[MAX_REDEEMER_LEN];
    int value;
    Unspent *usp;
} InputInfo;

typedef struct {
    InputInfo inputInfo[MAX_INPUTS];
    int inputInfo_count;
    OutputInfo outputInfo[MAX_OUTPUTS];
    int outputInfo_count;
    Interval validityInterval;
    int thisInput;
} Context;

extern Block Ledger[MAX_BLOCKS];
extern int block_count;
extern Block txpool;

void makeValIn_from_now(Tx *tx, double seconds);

Tx *lookupTx(char *txid);
int unspentTxOutput(Tx* tx, OutputRef *utxo, const char *validator);
int unspentOutput(OutputRef *utxo, const char *validator);

void printLedger();
void copyTx(Tx *destination_tx, Tx *source_tx);
void chainBlock();

#endif // LEDGER_H