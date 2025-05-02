#ifndef POREP_H
#define POREP_H

#include "Ledger.h"
#include <math.h>

int PoRep_Replicate(int id, char** tauD, char* data, int data_len, const unsigned char *key, const unsigned char *iv, char** replica);
void PoRep_Poll(int N, int *challenge);
void PoRep_Prove(char** replica, int N, int id, int *challenge, char** proof);
bool PoRep_Verify_Oracle(char *d, int challenge, char **tauD, int N);
bool PoRep_Verify(int id, char **tau, int *challenge, int N, char** proof, const unsigned char *key, const unsigned char *iv);
void PoRep_Extract(int id, char **tau, char **replica, int N, const unsigned char *Provider_key, const unsigned char *Provider_iv, char *data);

#endif // POREP_H
