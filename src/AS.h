#ifndef ADAPTOR_SIGNATURE_H
#define ADAPTOR_SIGNATURE_H

#include "Ledger.h"

void AS_pSign(const EC_GROUP *group, const EC_POINT *AS_pubkey, const BIGNUM *AS_privkey, const EC_POINT *Y, BIGNUM *s_hat_out, BIGNUM *r_out, BN_CTX *ctx);
bool AS_pVrf(const EC_GROUP *group, const EC_POINT *AS_pubkey, BIGNUM *sig_s_hat, BIGNUM *sig_r, const EC_POINT *Y, BN_CTX *ctx);
void AS_Adapt(const EC_GROUP *group, BIGNUM *sig_s_hat, const BIGNUM *K, BN_CTX *ctx, BIGNUM *sig_s_out);
void AS_Ext(EC_GROUP *group, BIGNUM *sig_s_hat, Tx *finalTx, BN_CTX *ctx, BIGNUM *extracted_K);

#endif // ADAPTOR_SIGNATURE_H
