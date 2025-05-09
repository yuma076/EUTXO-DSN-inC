#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "Ledger.h"
#include "contractVal.h"

void genTxid(Tx *tx, char *txid);
bool verifyTx(Tx *tx);
void makeContext(Tx *tx, Context *cntxt);
void makeTx(char *validator, char *redeemer, char *input_datum, int value, const char *receiver_pub, char *output_datum, Tx *tx);

bool make_signRedeemer(const char *privkey_file, const unsigned char *data, unsigned char **sig, unsigned int *sig_len);
bool signValidator(Context *cntxt);
bool payTx(const char *sender_pub, const char *sender_priv, const char *receiver_pub, int value);

#endif // TRANSACTION_H