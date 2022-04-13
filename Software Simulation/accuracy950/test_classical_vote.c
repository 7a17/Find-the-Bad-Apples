#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define EXPERIMENT_TIMES 10000
#define VOTE_NUM 7
#define ACCURACY 950


int SCA_oracle(const unsigned char * ct, 
           const unsigned char * sk, 
           unsigned char * msg_A) 
{
    int ret = oracle(ct,sk,msg_A);
    unsigned int rand_num;
    randombytes(&rand_num,sizeof(rand_num));
    rand_num = rand_num % 1000;
    if(rand_num < (unsigned int)(1000-ACCURACY)) 
        ret = (ret + 1) & 1;
    return ret;
}

int SCA_oracle_vote(const unsigned char * ct, 
           const unsigned char * sk, 
           unsigned char * msg_A) 
{
    int ret=0;
	for(int i=0;i<VOTE_NUM;i++)
	{
		ret+=SCA_oracle(ct,sk,msg_A);
	}
    return (ret>(VOTE_NUM/2));
}

static int kyber_Attack(int r,int save[5]) {
    /* random init */
    unsigned char       rand_seed[48];
    unsigned char       entropy_input[48];
    srand(r);
    for (int i=0; i<48; i++)
        entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);

    /*pk sk ct*/
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];

    /* the s  recovered by adversary */
    signed char         recs[KYBER_K][KYBER_N] = { 0 };
    /* the polyvec form of true s */
    polyvec             skpoly = { { 0 } };
    polyvec             skpoly_recovered;

    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    m[0] = 0x1;         // first coeff of m is 1


    if (  crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {
        printf("crypto_kem_keypair error\n");
        return -1;
    }

    int query = 0;
	memset(&skpoly_recovered,0,sizeof(skpoly_recovered));


	for(int i = 0; i < KYBER_K; i++) {
		for(int k = 0; k < KYBER_N; k++) {
			kemenc_Attack_rec(ct, m, pk, 5, k, i);
			if(SCA_oracle(ct, sk, m) == 1) {
				query += 1;
				kemenc_Attack_rec(ct, m, pk, 4, k, i);
				if(SCA_oracle(ct, sk, m) == 0) {
					skpoly_recovered.vec[i].coeffs[k] = 0;
					query += 1;
				}
				else {
					query += 1;
					kemenc_Attack_rec(ct, m, pk, 3, k, i);
					if(SCA_oracle(ct, sk, m) == 0) {
						skpoly_recovered.vec[i].coeffs[k] = -1;
						query += 1;
					}
					else {
						query += 1;
						kemenc_Attack_rec(ct, m, pk, 2, k, i);
						if(SCA_oracle(ct, sk, m) == 0) {
							skpoly_recovered.vec[i].coeffs[k] = -2;
							query += 1;
						}
						else{
							skpoly_recovered.vec[i].coeffs[k] = -3;
							query += 1;
						}
					}   
				}
			}
			else {
				query += 1;
				kemenc_Attack_rec(ct, m, pk, 6, k, i);
				if(SCA_oracle(ct, sk, m) == 1) {
					skpoly_recovered.vec[i].coeffs[k] = 1;
					query += 1;
				}
				else {
					query += 1; 
					kemenc_Attack_rec(ct, m, pk, 7, k, i);
					if(SCA_oracle(ct, sk, m) == 1) {
						skpoly_recovered.vec[i].coeffs[k] = 2;
						query += 1;
					}
					else{
						skpoly_recovered.vec[i].coeffs[k] = 3;
						query += 1;
					}
				}
			}
		}
	}

	int checks = 0;
	for(int i = 0; i < KYBER_K; i++) {
		for(int j = 0; j < KYBER_N; j++) {
			if(skpoly_recovered.vec[i].coeffs[j] != skpoly.vec[i].coeffs[j]) {
				checks++;
				//printf("error s in s[%d][%d] \n", i, j);
			}
		}
	}
	save[0] = query;
	save[1] = checks;
	query = 0;


	for(int i = 0; i < KYBER_K; i++) {
		for(int k = 0; k < KYBER_N; k++) {
			kemenc_Attack_rec(ct, m, pk, 5, k, i);
			if(SCA_oracle_vote(ct, sk, m) == 1) {
				query += VOTE_NUM;
				kemenc_Attack_rec(ct, m, pk, 4, k, i);
				if(SCA_oracle_vote(ct, sk, m) == 0) {
					skpoly_recovered.vec[i].coeffs[k] = 0;
					query += VOTE_NUM;
				}
				else {
					query += VOTE_NUM;
					kemenc_Attack_rec(ct, m, pk, 3, k, i);
					if(SCA_oracle_vote(ct, sk, m) == 0) {
						skpoly_recovered.vec[i].coeffs[k] = -1;
						query += VOTE_NUM;
					}
					else {
						query += VOTE_NUM;
						kemenc_Attack_rec(ct, m, pk, 2, k, i);
						if(SCA_oracle_vote(ct, sk, m) == 0) {
							skpoly_recovered.vec[i].coeffs[k] = -2;
							query += VOTE_NUM;
						}
						else{
							skpoly_recovered.vec[i].coeffs[k] = -3;
							query += VOTE_NUM;
						}
					}   
				}
			}
			else {
				query += VOTE_NUM;
				kemenc_Attack_rec(ct, m, pk, 6, k, i);
				if(SCA_oracle_vote(ct, sk, m) == 1) {
					skpoly_recovered.vec[i].coeffs[k] = 1;
					query += VOTE_NUM;
				}
				else {
					query += VOTE_NUM; 
					kemenc_Attack_rec(ct, m, pk, 7, k, i);
					if(SCA_oracle_vote(ct, sk, m) == 1) {
						skpoly_recovered.vec[i].coeffs[k] = 2;
						query += VOTE_NUM;
					}
					else{
						skpoly_recovered.vec[i].coeffs[k] = 3;
						query += VOTE_NUM;
					}
				}
			}
		}
	}

    save[2] = query;


    checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j++) {
            if(skpoly_recovered.vec[i].coeffs[j] != skpoly.vec[i].coeffs[j]) {
                checks++;
            }
        }
    }
    save[3] = checks;
}


int
main(int argc, char * argv[])
{
    FILE * fp = fopen("result_classical_vote.csv","w");
    fprintf(fp,"recovery_query,ori_err_cof,query_with_vote,err_cof\n");
    for(int i=1;i<=EXPERIMENT_TIMES;i++)
    {
        int tmp[5];
        kyber_Attack(i,tmp);
        fprintf(fp,"%d,%d,%d,%d\n",tmp[0],tmp[1],tmp[2],tmp[3]);
        if(i % 1000 == 0)
            printf("done %d tests...\n",i);
    }
    fclose(fp);
    return 0;

}

