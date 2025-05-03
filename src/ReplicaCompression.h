#ifndef REPLICA_COMPRESSION_H
#define REPLICA_COMPRESSION_H

#include "PoRep.h"

bool lookupproof(int ch, char *ext_proof);
void PoRep_Prove_malicious(char **replica, int N, int id, int *challenge, char **proof);
void PoRep_Extract_malicious(int id, char **tauD, char **replica, int N, const unsigned char *Provider_key, const unsigned char *Provider_iv, char *data);

#endif // REPLICA_COMPRESSION_H
