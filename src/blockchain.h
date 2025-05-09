#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "Transaction.h"
#include "AS.h"
#include "ReplicaCompression.h"

//#define MODE_BURNT (0) // MODE_BURNT (0/1) -> 0 is the case of delete replica, 1 is the case of invalid interval.

bool partial_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, const char *receiver_pub, int payment);
bool complete_contractTx(Tx *tx, const char* sender_pub, const char *sender_priv, int collateral);
bool testTx(int id, char** replica, int N, int collateral, char **tauD, unsigned char *Provider_key, unsigned char *Provider_iv);
void partial_finalTx(Tx *tx, BIGNUM *sig_s_hat, BIGNUM *sig_r);
bool complete_finalTx(const EC_GROUP *group, Tx *tx, const EC_POINT *AS_pubkey, const EC_POINT *Y, const BIGNUM *K, BN_CTX *ctx, const char *receiver_pub, int collateral);

#endif // BLOCKCHAIN_H