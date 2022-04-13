#include <iostream>

#define KYBER_Q 3329

typedef struct _ctinfo
{
	int c1;
	int c2;
	int c3;
	int c4;
	int v;
}ct_info;

typedef struct _attackinfo{
	int aval;
	ct_info ct1;
	int ct1_res;
	ct_info ct2;
	int ct2_res;
}attack_info;


int cof_512[7] = {-3,-2,-1,0,1,2,3};

static int POS4(int a,int b,int c,int d){
	return a + b*7 + c*49 + d * 49*7;
}

attack_info gl_info[49*49];

void init_attackinfo()
{
	FILE * fp = fopen("data.txt","r");
	if(fp == NULL){
		printf("err read file!");
		exit(0);
	}
	for(int i=0;i<49*49;i++){
		int unused;
		fscanf(fp,"%d,%d,%d,%d,%d,",&unused,&unused,&unused,&unused,&gl_info[i].aval);
		fscanf(fp,"%d,%d,%d,%d,%d,%d,",&gl_info[i].ct1.c1,&gl_info[i].ct1.c2,&gl_info[i].ct1.c3,&gl_info[i].ct1.c4,&gl_info[i].ct1.v,&gl_info[i].ct1_res);
		fscanf(fp,"%d,%d,%d,%d,%d,%d\n",&gl_info[i].ct2.c1,&gl_info[i].ct2.c2,&gl_info[i].ct2.c3,&gl_info[i].ct2.c4,&gl_info[i].ct2.v,&gl_info[i].ct2_res);
	}
}

int main(int argc, char *argv[]) {
	int aval_cnt = 0,checked_cnt = 0;
	init_attackinfo();
	for(int r=0;r<49*49;r++){
		if(gl_info[r].aval == 0){
			//printf("i = %d, not available, ignore...\n",r);
			continue;
		}
		aval_cnt++;
		int tmp_result1[7*7*7*7],tmp_result2[7*7*7*7];
		int v1,c11,c21,c31,c41,v2,c12,c22,c32,c42;
		c11=gl_info[r].ct1.c1,c21=gl_info[r].ct1.c2,c31=gl_info[r].ct1.c3,c41=gl_info[r].ct1.c4,v1=gl_info[r].ct1.v;
		c12=gl_info[r].ct2.c1,c22=gl_info[r].ct2.c2,c32=gl_info[r].ct2.c3,c42=gl_info[r].ct2.c4,v2=gl_info[r].ct2.v;
		
		int choose_u11 = (int)(KYBER_Q*c11/1024.0 + 0.5);
		int choose_u21 = (int)(KYBER_Q*c21/1024.0 + 0.5);
		int choose_u31 = (int)(KYBER_Q*c31/1024.0 + 0.5);
		int choose_u41 = (int)(KYBER_Q*c41/1024.0 + 0.5);
		
		int choose_u12 = (int)(KYBER_Q*c12/1024.0 + 0.5);
		int choose_u22 = (int)(KYBER_Q*c22/1024.0 + 0.5);
		int choose_u32 = (int)(KYBER_Q*c32/1024.0 + 0.5);
		int choose_u42 = (int)(KYBER_Q*c42/1024.0 + 0.5);
		
		for(int i1=0;i1<7;i1++){
			for(int i2=0;i2<7;i2++){
				for(int i3=0;i3<7;i3++){
					for(int i4=0;i4<7;i4++){
						float tmp = (2.0/KYBER_Q * ((int)(KYBER_Q/16.0*v1 + 0.5) - (cof_512[i1] * choose_u11 + cof_512[i2] * choose_u21 + cof_512[i3] * choose_u31 + cof_512[i4] * choose_u41)));
						int rst;
						if(tmp > 0)
							tmp_result1[POS4(i1, i2, i3, i4)] = (int)(tmp+0.5) & 1;
						else
							tmp_result1[POS4(i1, i2, i3, i4)] = (int)(tmp-0.5) & 1;
					}
				}
			}
		}
		
		for(int i1=0;i1<7;i1++){
			for(int i2=0;i2<7;i2++){
				for(int i3=0;i3<7;i3++){
					for(int i4=0;i4<7;i4++){
						float tmp = (2.0/KYBER_Q * ((int)(KYBER_Q/16.0*v2 + 0.5) - (cof_512[i1] * choose_u12 + cof_512[i2] * choose_u22 + cof_512[i3] * choose_u32+  cof_512[i4] * choose_u42 )));
						int rst;
						if(tmp > 0)
							tmp_result2[POS4(i1, i2, i3, i4)] = (int)(tmp+0.5) & 1;
						else
							tmp_result2[POS4(i1, i2, i3, i4)] = (int)(tmp-0.5) & 1;
					}
				}
			}
		}
		
		int cnt00=0,cnt01=0,cnt10=0,cnt11=0;
		
		for(int i=0;i<7*7*7*7;i++){
			if(tmp_result1[i] == 0 && tmp_result2[i] == 0){
				cnt00++;
			}
			else if(tmp_result1[i] == 0 && tmp_result2[i] == 1){
				cnt01++;
			}
			else if(tmp_result1[i] == 1 && tmp_result2[i] == 0){
				cnt10++;
			}
			else if(tmp_result1[i] == 1 && tmp_result2[i] == 1){
				cnt11++;
			}
		}
		int a,b,c,d;
		d = r%7;
		c = (r%49)/7;
		b = r/49%7;
		a = r/49/7;
		printf("cnt00 = %4d, cnt01 = %4d, cnt10 = %4d, cnt11 = %4d\n",cnt00,cnt01,cnt10,cnt11);
		if(cnt00==1 && gl_info[r].ct1_res == 0 && gl_info[r].ct2_res == 0){
			for(int i=0;i<7*7*7*7;i++){
				if(tmp_result1[i] == 0 && tmp_result2[i] == 0){
					if(i%7 == a && (i%49)/7 == b && i/49%7 == c && i/49/7 == d){
						//printf("we can indentify i = %d. i.e. (%d,%d,%d,%d)\n",i,a,b,c,d);
						checked_cnt++;
						break;
					}
				}
			}
		}
		if(cnt01==1 && gl_info[r].ct1_res == 0 && gl_info[r].ct2_res == 1){
			for(int i=0;i<7*7*7*7;i++){
				if(tmp_result1[i] == 0 && tmp_result2[i] == 1){
					if(i%7 == a && (i%49)/7 == b && i/49%7 == c && i/49/7 == d){
						//printf("we can indentify i = %d. i.e. (%d,%d,%d,%d)\n",i,a,b,c,d);
						checked_cnt++;
						break;
					}
				}
			}
		}
		
		if(cnt10==1 && gl_info[r].ct1_res == 1 && gl_info[r].ct2_res == 0){
			for(int i=0;i<7*7*7*7;i++){
				if(tmp_result1[i] == 1 && tmp_result2[i] == 0){
					if(i%7 == a && (i%49)/7 == b && i/49%7 == c && i/49/7 == d){
						//printf("we can indentify i = %d. i.e. (%d,%d,%d,%d)\n",i,a,b,c,d);
						checked_cnt++;
						break;
					}
				}
			}
		}
		if(cnt11==1 && gl_info[r].ct1_res == 1 && gl_info[r].ct2_res == 1){
			for(int i=0;i<7*7*7*7;i++){
				if(tmp_result1[i] == 1 && tmp_result2[i] == 1){
					if(i%7 == a && (i%49)/7 == b && i/49%7 == c && i/49/7 == d){
						//printf("we can indentify i = %d. i.e. (%d,%d,%d,%d)\n",i,a,b,c,d);
						checked_cnt++;
						break;
					}
				}
			}
		}
		
	}
	printf("aval = %d, checked_success = %d.\n",aval_cnt,checked_cnt);
}

