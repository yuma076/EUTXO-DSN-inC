#include "AS.h"

void AS_pSign(const EC_GROUP *group, const EC_POINT *AS_pubkey, const BIGNUM *AS_privkey, const EC_POINT *Y, BIGNUM *s_hat_out, BIGNUM *r_out, BN_CTX *ctx) {
    BIGNUM *k = BN_new(), *r = BN_new(), *s_hat = BN_new(), *order = BN_new(), *e = BN_new(); // processed free
    EC_POINT *Gk = EC_POINT_new(group); // processed free
    char *hex_AS_pubkey, *hex_Gk, *hex_Y;

    EC_GROUP_get_order(group, order, ctx);
    BN_rand_range(k, order);
    EC_POINT_mul(group, Gk, k, NULL, NULL, ctx);
    hex_AS_pubkey = EC_POINT_point2hex(group, AS_pubkey, POINT_CONVERSION_COMPRESSED, ctx); // processed free
    hex_Gk = EC_POINT_point2hex(group, Gk, POINT_CONVERSION_COMPRESSED, ctx); // processed free
    hex_Y = EC_POINT_point2hex(group, Y, POINT_CONVERSION_COMPRESSED, ctx); // processed free
    unsigned char concat[1133] = {};
    size_t AS_pubkey_len = strlen(hex_AS_pubkey);
    size_t Gk_len = strlen(hex_Gk);
    size_t Y_len = strlen(hex_Y);
    memcpy(concat, hex_AS_pubkey, AS_pubkey_len);
    memcpy(concat + AS_pubkey_len, hex_Gk, Gk_len);
    memcpy(concat + AS_pubkey_len + Gk_len, hex_Y, Y_len);

    unsigned char hash[BIN_HASH_SIZE] = {};
    calcHash(concat, AS_pubkey_len + Gk_len + Y_len, hash);
    BN_bin2bn(hash, BIN_HASH_SIZE, r);

    BN_mod_mul(e, r, AS_privkey, order, ctx);
    BN_mod_add(s_hat, k, e, order, ctx);

    BN_copy(s_hat_out, s_hat);
    BN_copy(r_out, r);

    BN_free(k); BN_free(r); BN_free(s_hat); BN_free(order); BN_free(e);
    EC_POINT_free(Gk);
    OPENSSL_free(hex_AS_pubkey); OPENSSL_free(hex_Gk); OPENSSL_free(hex_Y);
}

bool AS_pVrf(const EC_GROUP *group, const EC_POINT *AS_pubkey, BIGNUM *sig_s_hat, BIGNUM *sig_r, const EC_POINT *Y, BN_CTX *ctx){
    BIGNUM *order = BN_new(), *minus_sig_r = BN_new(), *rd = BN_new(); // processed free
    EC_POINT *Gs_hat = EC_POINT_new(group), *PKR = EC_POINT_new(group), *Gk = EC_POINT_new(group); // processed free
    char *hex_AS_pubkey, *hex_Gk, *hex_Y;

    EC_GROUP_get_order(group, order, ctx);
    EC_POINT_mul(group, Gs_hat, sig_s_hat, NULL, NULL, ctx);
    BN_copy(minus_sig_r, sig_r);
    BN_set_negative(minus_sig_r, 1);
    EC_POINT_mul(group, PKR, NULL, AS_pubkey, minus_sig_r, ctx);
    EC_POINT_add(group, Gk, Gs_hat, PKR, ctx);
    hex_AS_pubkey = EC_POINT_point2hex(group, AS_pubkey, POINT_CONVERSION_COMPRESSED, ctx); // processed free
    hex_Gk = EC_POINT_point2hex(group, Gk, POINT_CONVERSION_COMPRESSED, ctx); // processed free
    hex_Y = EC_POINT_point2hex(group, Y, POINT_CONVERSION_COMPRESSED, ctx); // processed free
    unsigned char concat[1133] = {};
    size_t AS_pubkey_len = strlen(hex_AS_pubkey);
    size_t Gk_len = strlen(hex_Gk);
    size_t Y_len = strlen(hex_Y);
    memcpy(concat, hex_AS_pubkey, AS_pubkey_len);
    memcpy(concat + AS_pubkey_len, hex_Gk, Gk_len);
    memcpy(concat + AS_pubkey_len + Gk_len, hex_Y, Y_len);

    unsigned char hash[BIN_HASH_SIZE] = {};
    calcHash(concat, AS_pubkey_len + Gk_len + Y_len, hash);
    BN_bin2bn(hash, BIN_HASH_SIZE, rd);
    bool result = (BN_cmp(rd, sig_r) == 0);

    BN_free(order); BN_free(rd);
    EC_POINT_free(Gs_hat); EC_POINT_free(PKR); EC_POINT_free(Gk);
    OPENSSL_free(hex_AS_pubkey); OPENSSL_free(hex_Gk); OPENSSL_free(hex_Y);

    return result;
}

void AS_Adapt(const EC_GROUP *group, BIGNUM *sig_s_hat, const BIGNUM *K, BN_CTX *ctx, BIGNUM *sig_s_out) {
    BIGNUM *order = BN_new(); // processed free
    EC_GROUP_get_order(group, order, ctx);
    BN_mod_add(sig_s_out, sig_s_hat, K, order, ctx);

    BN_free(order);
}

void AS_Ext(EC_GROUP *group, BIGNUM *sig_s_hat, Tx *finalTx, BN_CTX *ctx, BIGNUM *Uext_K) {
    char redeemer[MAX_REDEEMER_LEN] = {};
    char *hex_sig_s;
    strcpy(redeemer, finalTx->inputs[0].redeemer);
    strtok(redeemer, ","); strtok(NULL, ","); strtok(NULL, ","); strtok(NULL, ",");
    hex_sig_s = strtok(NULL, ",");
    BIGNUM *sig_s = BN_new(), *order = BN_new(); // processed free
    EC_GROUP_get_order(group, order, ctx);
    BN_hex2bn(&sig_s, hex_sig_s);
    BN_set_negative(sig_s_hat, 1);
    BN_mod_add(Uext_K, sig_s, sig_s_hat, order, ctx);

    BN_set_negative(sig_s_hat, 0);
    BN_free(sig_s); BN_free(order);
}