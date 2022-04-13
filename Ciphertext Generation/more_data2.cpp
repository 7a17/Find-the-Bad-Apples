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

int P(int a,int b,int c,int d){
	return a*7*7*7 + b*7*7 + c*7 + d;
	
}

int main(int argc, char *argv[]) {
	int aval_cnt = 0,checked_cnt = 0;
	int gen = 0;
	init_attackinfo();
	for(int r=0;r<49*49;r++){
		if(gl_info[r].aval == 0){
			int a,b,c,d;
			d = r%7;
			c = (r%49)/7;
			b = r/49%7;
			a = r/49/7;
			if(gl_info[P(a,b,6-c,6-d)].aval == 1){
				gl_info[r].aval = 1;
				gl_info[r].ct1_res = gl_info[P(a,b,6-c,6-d)].ct1_res;
				gl_info[r].ct2_res = gl_info[P(a,b,6-c,6-d)].ct2_res;
				
				gl_info[r].ct1.c1 = gl_info[P(a,b,6-c,6-d)].ct1.c1;
				gl_info[r].ct1.c2 = gl_info[P(a,b,6-c,6-d)].ct1.c2;
				gl_info[r].ct1.c3 = 1024-gl_info[P(a,b,6-c,6-d)].ct1.c3;
				gl_info[r].ct1.c4 = 1024-gl_info[P(a,b,6-c,6-d)].ct1.c4;
				gl_info[r].ct1.v = gl_info[P(a,b,6-c,6-d)].ct1.v;
				
				gl_info[r].ct2.c1 = gl_info[P(a,b,6-c,6-d)].ct2.c1;
				gl_info[r].ct2.c2 = gl_info[P(a,b,6-c,6-d)].ct2.c2;
				gl_info[r].ct2.c3 = 1024-gl_info[P(a,b,6-c,6-d)].ct2.c3;
				gl_info[r].ct2.c4 = 1024-gl_info[P(a,b,6-c,6-d)].ct2.c4;
				gl_info[r].ct2.v = gl_info[P(a,b,6-c,6-d)].ct2.v;
				gen++;
				continue;
			}
		}
	}
	printf("gen=%d\n",gen);
	
	for(int i1=0;i1<7;i1++){
		for(int i2=0;i2<7;i2++){
			for(int i3=0;i3<7;i3++){
				for(int i4=0;i4<7;i4++){
					attack_info tmp = gl_info[P(i1, i2, i3, i4)];
					printf("%d,%d,%d,%d,",i1,i2,i3,i4);
					printf("%d,",tmp.aval);
					printf("%d,%d,%d,%d,%d,",tmp.ct1.c1,tmp.ct1.c2,tmp.ct1.c3,tmp.ct1.c4,tmp.ct1.v);
					printf("%d,",tmp.ct1_res);
					printf("%d,%d,%d,%d,%d,",tmp.ct2.c1,tmp.ct2.c2,tmp.ct2.c3,tmp.ct2.c4,tmp.ct2.v);
					printf("%d\n",tmp.ct2_res);
					
				}
			}
		}
	}
}

