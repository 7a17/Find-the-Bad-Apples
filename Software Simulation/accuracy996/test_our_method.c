#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define EXPERIMENT_TIMES 10000
#define ACCURACY 996

attack_info gl_info[49*49];

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
                //printf("k=%d,change!\n",k);
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

    for(int i = 0; i < KYBER_K; i++) {
        gene_taskinfo(&skpoly_recovered,task_list,i);
        for(int k = 0; k < KYBER_N/4; k++) {
            int a,b,c,d,res_1,res_2;
            a = skpoly_recovered.vec[i].coeffs[task_list[k*4]];
            b = skpoly_recovered.vec[i].coeffs[task_list[k*4+1]];
            c = skpoly_recovered.vec[i].coeffs[task_list[k*4+2]];
            d = skpoly_recovered.vec[i].coeffs[task_list[k*4+3]];
            atk = get_attack_info(a,b,c,d);
            // printf("debug=%d,%d,%d,%d\n",a+3,b+3,c+3,d+3);
            // printf("debug=%d,%d,%d,%d,%d\n",atk.ct1.c1,atk.ct1.c2,atk.ct1.c3,atk.ct1.c4,atk.ct1.v);
            kemenc_Attack(ct, m, pk, atk.ct1, k, i, task_list);
            res_1 = SCA_oracle(ct, sk, m);
            kemenc_Attack(ct, m, pk, atk.ct2, k, i, task_list);
            res_2 = SCA_oracle(ct, sk, m);
            if (res_1 == atk.ct1_res && res_2 == atk.ct2_res)
            {
                // printf("k = %d, block = %d, ok!\n",i,k);
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
            }
            query_check += 2;
        }
    }


    save[2] = query_check;
    int query_reclt = 0;
    for(int j = 0; j < err_cof_cnt; j++) {
        int i = err_cof_i[j];
        int k = err_cof_k[j];
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
    fprintf(fp,"recovery_query,ori_err_cof,check_query,recollect_query,err_cof,total_query\n");
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

