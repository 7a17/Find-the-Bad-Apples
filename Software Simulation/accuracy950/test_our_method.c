#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define MAX_ROUND 20
#define CC1 4
#define CC2 3
#define ACCURACY 950
#define EXPERIMENT_TIMES 10000

attack_info gl_info[49*49];
int roundarr[MAX_ROUND] = {5,9,12,13,13,16,17,17,21,21,21,21,21,21,21,21,21,21,21,21};


void init_attackinfo()
{
    FILE * fp = fopen("data.txt","r");
    if(fp == NULL)
    {
        printf("err read file!");
        exit(0);
    }
    for(int i=0;i<49*49;i++)
    {
        int unused;
        fscanf(fp,"%d,%d,%d,%d,%d,",&unused,&unused,&unused,&unused,&gl_info[i].aval);
        fscanf(fp,"%d,%d,%d,%d,%d,%d,",&gl_info[i].ct1.c1,&gl_info[i].ct1.c2,&gl_info[i].ct1.c3,&gl_info[i].ct1.c4,&gl_info[i].ct1.v,&gl_info[i].ct1_res);
        fscanf(fp,"%d,%d,%d,%d,%d,%d\n",&gl_info[i].ct2.c1,&gl_info[i].ct2.c2,&gl_info[i].ct2.c3,&gl_info[i].ct2.c4,&gl_info[i].ct2.v,&gl_info[i].ct2_res);
    }
}

attack_info get_attack_info(int a,int b,int c,int d)
{
    return gl_info[(d+3)+(c+3)*7+(b+3)*49+(a+3)*49*7];
}

void gene_taskinfo(polyvec * skpoly_recovered, int task_list[256],int i)
{
    attack_info atk;
    for(int i=0;i<256;i++)
    {
        task_list[i] = i;
    }
	for (int i=256-1;i>=0;--i) 
	{
		int rd = rand()%(i+1);
		int tmp = task_list[rd];
		task_list[rd] = task_list[i];
		task_list[i] = tmp;
	}
    for(int k=0;k<64;k++)
    {
        int a,b,c,d,res_1,res_2;
        a = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4]];
        b = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4+1]];
        c = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4+2]];
        d = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4+3]];
        atk = get_attack_info(a,b,c,d);
        if(atk.aval == 1)
        {
            continue;
        }
        else
        {
            int cir = 0;
            while(1)
            {
                int rd_this = k*4 + rand() % 4;
                int rd_other_block = rand() % 64;
                int rd_other = rd_other_block + rand() % 4;
                int tmp = task_list[rd_this];
                task_list[rd_this] = task_list[rd_other];
                task_list[rd_other] = tmp;

                a = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4]];
                b = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4+1]];
                c = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4+2]];
                d = skpoly_recovered->vec[i].coeffs[task_list[(k%64)*4+3]];
                atk = get_attack_info(a,b,c,d);
                if(atk.aval == 1)
                {
                    a = skpoly_recovered->vec[i].coeffs[task_list[(rd_other_block%64)*4]];
                    b = skpoly_recovered->vec[i].coeffs[task_list[(rd_other_block%64)*4+1]];
                    c = skpoly_recovered->vec[i].coeffs[task_list[(rd_other_block%64)*4+2]];
                    d = skpoly_recovered->vec[i].coeffs[task_list[(rd_other_block%64)*4+3]];
                    atk = get_attack_info(a,b,c,d);
                    if(atk.aval == 1)
                    {
                        break;
                    }
                    else
                    {
                        tmp = task_list[rd_this];
                        task_list[rd_this] = task_list[rd_other];
                        task_list[rd_other] = tmp;
                    }
                }
                else
                {
                        tmp = task_list[rd_this];
                        task_list[rd_this] = task_list[rd_other];
                        task_list[rd_other] = tmp;
                }
                cir++;
                if(cir>10000)
                    break;

            }
        }
    }
}

int getli(int round)
{
	return roundarr[round];
}


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

static int kyber_Attack(int r,int save[6]) {
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

    polyvec             skpoly_recovered = { { 0 } };
    /* the m set by adversary */
    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    m[0] = 0x1;         // first coeff of m is 1

    /* get key pair */
    if (  crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {
        printf("crypto_kem_keypair error\n");
        return -1;
    }
	
	
	struct{
		int confidence[7];//every cof confidence
		int most_possible_cof;//0~7
		int most_confidence;
		int isok;
	} cofc[2][256];
	memset(cofc,0,sizeof(cofc));
	int already=0;
	
	
    int query = 0;

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
			int value = skpoly_recovered.vec[i].coeffs[k];
			cofc[i][k].most_possible_cof = value+3;
			cofc[i][k].most_confidence = 1;
			cofc[i][k].confidence[value+3] = 1;
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



    int query_check = 0;
    attack_info atk;
    int task_list[256];

    int err_cof_cnt = 0;
    int err_cof_i[512];
    int err_cof_k[512];
	int query_reclt = 0;
	int erral = 0;
	int confidence[2][256];
	memset(confidence,0,sizeof(confidence));
	for(int round=0;round<MAX_ROUND;round++) {
		for(int i = 0; i < KYBER_K; i++) {
			gene_taskinfo(&skpoly_recovered,task_list,i);
			// for(int j=0;j<256;j++)
			// {
			//     printf("%d ",task_list[j]);
			// }
			// printf("\n");
			for(int k = 0; k < KYBER_N/4; k++) {
				int a,b,c,d,res_1,res_2;
				a = skpoly_recovered.vec[i].coeffs[task_list[k*4]];
				b = skpoly_recovered.vec[i].coeffs[task_list[k*4+1]];
				c = skpoly_recovered.vec[i].coeffs[task_list[k*4+2]];
				d = skpoly_recovered.vec[i].coeffs[task_list[k*4+3]];
				if(cofc[i][task_list[k*4]].isok && cofc[i][task_list[k*4+1]].isok && cofc[i][task_list[k*4+2]].isok && cofc[i][task_list[k*4+3]].isok)
					continue;
				if(cofc[i][task_list[k*4]].most_confidence > getli(round) && cofc[i][task_list[k*4+1]].most_confidence > getli(round) && cofc[i][task_list[k*4+2]].most_confidence > getli(round) && cofc[i][task_list[k*4+3]].most_confidence > getli(round))
					continue;
				atk = get_attack_info(a,b,c,d);
				// printf("debug=%d,%d,%d,%d\n",a+3,b+3,c+3,d+3);
				// printf("debug=%d,%d,%d,%d,%d\n",atk.ct1.c1,atk.ct1.c2,atk.ct1.c3,atk.ct1.c4,atk.ct1.v);
				kemenc_Attack(ct, m, pk, atk.ct1, k, i, task_list);
				res_1 = SCA_oracle(ct, sk, m);
				kemenc_Attack(ct, m, pk, atk.ct2, k, i, task_list);
				res_2 = SCA_oracle(ct, sk, m);
				if (res_1 == atk.ct1_res && res_2 == atk.ct2_res)
				{
					int value = skpoly_recovered.vec[i].coeffs[task_list[k*4]];
					cofc[i][task_list[k*4]].confidence[value+3] += CC1;
					value = skpoly_recovered.vec[i].coeffs[task_list[k*4+1]];
					cofc[i][task_list[k*4+1]].confidence[value+3] += CC1;
					value = skpoly_recovered.vec[i].coeffs[task_list[k*4+2]];
					cofc[i][task_list[k*4+2]].confidence[value+3] += CC1;
					value = skpoly_recovered.vec[i].coeffs[task_list[k*4+3]];
					cofc[i][task_list[k*4+3]].confidence[value+3] += CC1;
				}
				else
				{
					err_cof_i[err_cof_cnt] = i;
					err_cof_i[err_cof_cnt+1] = i;
					err_cof_i[err_cof_cnt+2] = i;
					err_cof_i[err_cof_cnt+3] = i;

					err_cof_k[err_cof_cnt] = task_list[k*4];
					err_cof_k[err_cof_cnt+1] = task_list[k*4+1];
					err_cof_k[err_cof_cnt+2] = task_list[k*4+2];
					err_cof_k[err_cof_cnt+3] = task_list[k*4+3];
					err_cof_cnt+=4;
					// printf("k = %d, block = %d, error!\n",i,k);
					// printf("err in %d,%d,%d,%d\n",task_list[k*4],task_list[k*4+1],task_list[k*4+2],task_list[k*4+3]);
					// err_block[i] = k;
				}
				query_check += 2;
			}
		}

		save[2] = query_check;
		
		for(int j = 0; j < err_cof_cnt; j++) {
			int i = err_cof_i[j];
			int k = err_cof_k[j];
			if(cofc[i][k].isok)
				continue;
			if(cofc[i][k].most_confidence > getli(round))
				continue;
			kemenc_Attack_rec(ct, m, pk, 5, k, i);
			if(SCA_oracle(ct, sk, m) == 1) {
				query_reclt += 1;
				kemenc_Attack_rec(ct, m, pk, 4, k, i);
				if(SCA_oracle(ct, sk, m) == 0) {
					skpoly_recovered.vec[i].coeffs[k] = 0;
					query_reclt += 1;
				}
				else {
					query_reclt += 1;
					kemenc_Attack_rec(ct, m, pk, 3, k, i);
					if(SCA_oracle(ct, sk, m) == 0) {
						skpoly_recovered.vec[i].coeffs[k] = -1;
						query_reclt += 1;
					}
					else {
						query_reclt += 1;
						kemenc_Attack_rec(ct, m, pk, 2, k, i);
						if(SCA_oracle(ct, sk, m) == 0) {
							skpoly_recovered.vec[i].coeffs[k] = -2;
							query_reclt += 1;
						}
						else{
							skpoly_recovered.vec[i].coeffs[k] = -3;
							query_reclt += 1;
						}
					}   
				}
			}
			else {
				query_reclt += 1;
				kemenc_Attack_rec(ct, m, pk, 6, k, i);
				if(SCA_oracle(ct, sk, m) == 1) {
					skpoly_recovered.vec[i].coeffs[k] = 1;
					query_reclt += 1;
				}
				else {
					query_reclt += 1; 
					kemenc_Attack_rec(ct, m, pk, 7, k, i);
					if(SCA_oracle(ct, sk, m) == 1) {
						skpoly_recovered.vec[i].coeffs[k] = 2;
						query_reclt += 1;
					}
					else{
						skpoly_recovered.vec[i].coeffs[k] = 3;
						query_reclt += 1;
					}
				}
			}
			
			int value = skpoly_recovered.vec[i].coeffs[k];
			cofc[i][k].confidence[value+3] += CC2;
		}
		//update
		for(int i=0;i<2;i++){
		for(int k = 0; k < KYBER_N; k++) {
			for(int v=0;v<7;v++)
			{
				if(cofc[i][k].confidence[v] >= cofc[i][k].most_confidence)
				{
					cofc[i][k].most_possible_cof = v;
					cofc[i][k].most_confidence=cofc[i][k].confidence[v];
				}
			}
			if(!cofc[i][k].isok && cofc[i][k].most_confidence > getli(round))
			{
				cofc[i][k].isok = 1;
				already++;
			}
				
			skpoly_recovered.vec[i].coeffs[k] = cofc[i][k].most_possible_cof-3;
		}
		}
		err_cof_cnt=0;
	}

	
    save[3] = query_reclt;
    checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j++) {
            if(skpoly_recovered.vec[i].coeffs[j] != skpoly.vec[i].coeffs[j]) {
                checks++;
                //printf("error s in s[%d][%d] ", i, j);
            }
        }
    }
    save[4] = checks;

    save[5] = query+query_check+query_reclt;

}



int
main(int argc, char * argv[])
{
    init_attackinfo();
    FILE * fp = fopen("result_our_method.csv","w");
    fprintf(fp,"recovery_query,err_without_check,check_query,recollect_query,err_with_check,total_query\n");
    for(int i=1;i<=EXPERIMENT_TIMES;i++)
    {
        int tmp[6];
        kyber_Attack(i,tmp);
        fprintf(fp,"%d,%d,%d,%d,%d,%d\n",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]);
        if(i % 1000 == 0)
            printf("done %d tests...\n",i);
    }
    fclose(fp);
    return 0;

}

