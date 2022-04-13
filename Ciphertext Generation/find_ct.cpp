#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <string.h>
#include <unordered_map>
#include <vector>

using namespace std;

#define KYBER_Q 3329
int cof_512[7] = {-3,-2,-1,0,1,2,3};

typedef struct _ct_info{
	int c1;
	int c2;
	int v;
} ct_info;

typedef struct _ct_info4{
	int c1;
	int c2;
	int c3;
	int c4;
	int v;
} ct_info4;

typedef struct _tw_info{
	vector<int> idx1s;
	vector<int> idx2s;
} tw_info;

typedef struct _idf{
	int aval;
	ct_info4 ct1;
	int ct1_res;
	ct_info4 ct2;
	int ct2_res;
}idf;

idf final_result[7*7*7*7];
int g2_flag[7*7];
int total = 0;

typedef vector<ct_info> ct_infos;
//typedef vector<ct_info3> ct_infos3;
typedef vector<ct_info4> ct_infos4;
unordered_map<string,ct_infos> choices;
//unordered_map<string,ct_infos3> choices3;
unordered_map<string,ct_infos4> choices4;


static int POS(int a,int b){
	return a + b*7;
}

//static int POS3(int a,int b,int c){
//	return a + b*7 + c*49;
//}

static int POS4(int a,int b,int c,int d){
	return a + b*7 + c*49 + d*49*7;
}

int check_already(int a,int b,int c,int d){
	if(final_result[POS4(a, b, c, d)].aval != 0)
		return 1;
	return 0;
}

void append_res(int a,int b,int c,int d,ct_info4 ct1,int ct1_res,ct_info4 ct2,int ct2_res){
	if(check_already(a, b, c, d) == 0){
		g2_flag[POS(a, b)] = 1;
		final_result[POS4(a, b, c, d)].aval = 1;
		final_result[POS4(a, b, c, d)].ct1 = ct1;
		final_result[POS4(a, b, c, d)].ct1_res = ct1_res;
		final_result[POS4(a, b, c, d)].ct2 = ct2;
		final_result[POS4(a, b, c, d)].ct2_res = ct2_res;
		total++;
	}
	if(check_already(a, b, d, c) == 0){
		g2_flag[POS(a, b)] = 1;
		final_result[POS4(a, b, d, c)].aval = 1;
		final_result[POS4(a, b, d, c)].ct1.c1 = ct1.c1;
		final_result[POS4(a, b, d, c)].ct1.c2 = ct1.c2;
		final_result[POS4(a, b, d, c)].ct1.c3 = ct1.c4;
		final_result[POS4(a, b, d, c)].ct1.c4 = ct1.c3;
		final_result[POS4(a, b, d, c)].ct1.v = ct1.v;
		final_result[POS4(a, b, d, c)].ct1_res = ct1_res;
		final_result[POS4(a, b, d, c)].ct2.c1 = ct2.c1;
		final_result[POS4(a, b, d, c)].ct2.c2 = ct2.c2;
		final_result[POS4(a, b, d, c)].ct2.c3 = ct2.c4;
		final_result[POS4(a, b, d, c)].ct2.c4 = ct2.c3;
		final_result[POS4(a, b, d, c)].ct2.v = ct2.v;
		final_result[POS4(a, b, d, c)].ct2_res = ct2_res;
		total++;
	}
	if(check_already(b, a, c, d) == 0){
		g2_flag[POS(b, a)] = 1;
		final_result[POS4(b, a, c, d)].aval = 1;
		final_result[POS4(b, a, c, d)].ct1.c1 = ct1.c2;
		final_result[POS4(b, a, c, d)].ct1.c2 = ct1.c1;
		final_result[POS4(b, a, c, d)].ct1.c3 = ct1.c3;
		final_result[POS4(b, a, c, d)].ct1.c4 = ct1.c4;
		final_result[POS4(b, a, c, d)].ct1.v = ct1.v;
		final_result[POS4(b, a, c, d)].ct1_res = ct1_res;
		final_result[POS4(b, a, c, d)].ct2.c1 = ct2.c2;
		final_result[POS4(b, a, c, d)].ct2.c2 = ct2.c1;
		final_result[POS4(b, a, c, d)].ct2.c3 = ct2.c3;
		final_result[POS4(b, a, c, d)].ct2.c4 = ct2.c4;
		final_result[POS4(b, a, c, d)].ct2.v = ct2.v;
		final_result[POS4(b, a, c, d)].ct2_res = ct2_res;
		total++;
	}
	if(check_already(b, a, d, c) == 0){
		g2_flag[POS(b, a)] = 1;
		final_result[POS4(b, a, d, c)].aval = 1;
		final_result[POS4(b, a, d, c)].ct1.c1 = ct1.c2;
		final_result[POS4(b, a, d, c)].ct1.c2 = ct1.c1;
		final_result[POS4(b, a, d, c)].ct1.c3 = ct1.c4;
		final_result[POS4(b, a, d, c)].ct1.c4 = ct1.c3;
		final_result[POS4(b, a, d, c)].ct1.v = ct1.v;
		final_result[POS4(b, a, d, c)].ct1_res = ct1_res;
		final_result[POS4(b, a, d, c)].ct2.c1 = ct2.c2;
		final_result[POS4(b, a, d, c)].ct2.c2 = ct2.c1;
		final_result[POS4(b, a, d, c)].ct2.c3 = ct2.c4;
		final_result[POS4(b, a, d, c)].ct2.c4 = ct2.c3;
		final_result[POS4(b, a, d, c)].ct2.v = ct2.v;
		final_result[POS4(b, a, d, c)].ct2_res = ct2_res;
		total++;
	}
}

string uintarr2str(uint8_t * arr){
	string res = "";
	for(int i=0;i<48;i+=8){
		uint8_t tmp = 0;
		tmp |= arr[i]<<7;
		tmp |= arr[i+1]<<6;
		tmp |= arr[i+2]<<5;
		tmp |= arr[i+3]<<4;
		tmp |= arr[i+4]<<3;
		tmp |= arr[i+5]<<2;
		tmp |= arr[i+6]<<1;
		tmp |= arr[i+7];
		res.append(1,tmp);
	}
	uint8_t tmp = 0;
	tmp |= arr[48];
	res.append(1,tmp);
	return res;
}

void str2uint(string str, uint8_t * arr){
	for(int i=0;i<48;i+=8){
		uint8_t tmp = 0;
		arr[i] = ((uint8_t)str[i/8] >> 7 ) & 1;
		arr[i+1] = ((uint8_t)str[i/8] >> 6 ) & 1;
		arr[i+2] = ((uint8_t)str[i/8] >> 5 ) & 1;
		arr[i+3] = ((uint8_t)str[i/8] >> 4 ) & 1;
		arr[i+4] = ((uint8_t)str[i/8] >> 3 ) & 1;
		arr[i+5] = ((uint8_t)str[i/8] >> 2 ) & 1;
		arr[i+6] = ((uint8_t)str[i/8] >> 1 ) & 1;
		arr[i+7] = ((uint8_t)str[i/8]) & 1;
	}
	arr[48] = (uint8_t)str[48/8] & 1;
	return;
}

//string uintarr2str3(uint8_t * arr){
//	string res = "";
//	for(int i=0;i<336;i+=8){
//		uint8_t tmp = 0;
//		tmp |= arr[i]<<7;
//		tmp |= arr[i+1]<<6;
//		tmp |= arr[i+2]<<5;
//		tmp |= arr[i+3]<<4;
//		tmp |= arr[i+4]<<3;
//		tmp |= arr[i+5]<<2;
//		tmp |= arr[i+6]<<1;
//		tmp |= arr[i+7];
//		res.append(1,tmp);
//	}
//	uint8_t tmp = 0;
//	tmp |= arr[336]<<7;
//	tmp |= arr[337]<<6;
//	tmp |= arr[338]<<5;
//	tmp |= arr[339]<<4;
//	tmp |= arr[340]<<3;
//	tmp |= arr[341]<<2;
//	tmp |= arr[342]<<1;
//	res.append(1,tmp);
//	return res;
//}
//
//void str2uint3(string str, uint8_t * arr){
//	for(int i=0;i<336;i+=8){
//		uint8_t tmp = 0;
//		arr[i] = ((uint8_t)str[i/8] >> 7 ) & 1;
//		arr[i+1] = ((uint8_t)str[i/8] >> 6 ) & 1;
//		arr[i+2] = ((uint8_t)str[i/8] >> 5 ) & 1;
//		arr[i+3] = ((uint8_t)str[i/8] >> 4 ) & 1;
//		arr[i+4] = ((uint8_t)str[i/8] >> 3 ) & 1;
//		arr[i+5] = ((uint8_t)str[i/8] >> 2 ) & 1;
//		arr[i+6] = ((uint8_t)str[i/8] >> 1 ) & 1;
//		arr[i+7] = ((uint8_t)str[i/8]) & 1;
//	}
//	arr[336] = ((uint8_t)str[336/8] >> 7 ) & 1;
//	arr[336+1] = ((uint8_t)str[336/8] >> 6 ) & 1;
//	arr[336+2] = ((uint8_t)str[336/8] >> 5 ) & 1;
//	arr[336+3] = ((uint8_t)str[336/8] >> 4 ) & 1;
//	arr[336+4] = ((uint8_t)str[336/8] >> 3 ) & 1;
//	arr[336+5] = ((uint8_t)str[336/8] >> 2 ) & 1;
//	arr[336+6] = ((uint8_t)str[336/8] >> 1 ) & 1;
//	return;
//}

string uintarr2str4(uint8_t * arr){
	string res = "";
	for(int i=0;i<2400;i+=8){
		uint8_t tmp = 0;
		tmp |= arr[i]<<7;
		tmp |= arr[i+1]<<6;
		tmp |= arr[i+2]<<5;
		tmp |= arr[i+3]<<4;
		tmp |= arr[i+4]<<3;
		tmp |= arr[i+5]<<2;
		tmp |= arr[i+6]<<1;
		tmp |= arr[i+7];
		res.append(1,tmp);
	}
	uint8_t tmp = 0;
	tmp |= arr[2400]<<7;
	res.append(1,tmp);
	return res;
}

void str2uint4(string str, uint8_t * arr){
	for(int i=0;i<2400;i+=8){
		uint8_t tmp = 0;
		arr[i] = ((uint8_t)str[i/8] >> 7 ) & 1;
		arr[i+1] = ((uint8_t)str[i/8] >> 6 ) & 1;
		arr[i+2] = ((uint8_t)str[i/8] >> 5 ) & 1;
		arr[i+3] = ((uint8_t)str[i/8] >> 4 ) & 1;
		arr[i+4] = ((uint8_t)str[i/8] >> 3 ) & 1;
		arr[i+5] = ((uint8_t)str[i/8] >> 2 ) & 1;
		arr[i+6] = ((uint8_t)str[i/8] >> 1 ) & 1;
		arr[i+7] = ((uint8_t)str[i/8]) & 1;
	}
	arr[2400] = ((uint8_t)str[2400/8] >> 7 ) & 1;
	return;
}




int main(int argc, char *argv[]) {
	memset(final_result, 0, sizeof(final_result));
	memset(g2_flag, 0, sizeof(g2_flag));
	
	int cnt = 0;
	for(int c1=0;c1<86;c1++){
		for(int c2=0;c2<86;c2++){
			uint8_t tmp_result[7*7];
			if(c1+c2>=86)
				continue;
			int choose_u1 = (int)(KYBER_Q*c1/1024.0 + 0.5);
			int choose_u2 = (int)(KYBER_Q*c2/1024.0 + 0.5);
			for(int j = 0;j<16;j++){
				for(int i1=0;i1<7;i1++){
					for(int i2=0;i2<7;i2++){
						float tmp = (2.0/KYBER_Q * ((int)(KYBER_Q/16.0*j + 0.5) - (cof_512[i1] * choose_u1 + cof_512[i2] * choose_u2)));
						int rst;
						if(tmp > 0)
							tmp_result[POS(i1, i2)] = (int)(tmp+0.5) & 1;
						else
							tmp_result[POS(i1, i2)] = (int)(tmp-0.5) & 1;
					}
				}
				ct_info nf = {c1,c2,j};
				string formed_str = uintarr2str(tmp_result);
				if(choices.find(formed_str) == end(choices)){
					ct_infos v;
					v.push_back(nf);
					choices.insert(make_pair(uintarr2str(tmp_result),v));
				}
				else{
					choices[formed_str].push_back(nf);
				}
			}
		}
		printf("c1=%d\n",c1);
	}
	
	int map_size = choices.size();
	auto res2d = new uint8_t[map_size][49];
	int * res2d_cnt = new int[map_size];
	tw_info * twinf = new tw_info[49];
	
	int ccnt = 0;
	for(auto x:choices){
		str2uint(x.first, res2d[ccnt]);
		res2d_cnt[ccnt++] = x.second.size();
	}
	for(int j=0;j<map_size;j++){
		for(int i=0;i<49;i++){
			printf("%d,",res2d[j][i]);
			if((i+1)%7==0)
				printf("\n");
		}
		printf("cnt=%d\n",res2d_cnt[j]);
	}
	printf("\n");
	for(int tar=0;tar<49;tar++){
		for(int i=0;i<map_size;i++){
			for(int j=i+1;j<map_size;j++){
				int d1 = res2d[i][tar];
				int d2 = res2d[j][tar];
				int fail=0;
				for(int k=0;k<49;k++){
					if(k==tar)
						continue;
					if(res2d[i][k] == d1 && res2d[j][k] == d2){
						fail = 1;
						break;
					}
				}
				if(fail != 1){
					int cnt1=0;
					int xor_res[49];
					for (int t=0; t<49; t++) {
						xor_res[t] =  res2d[i][t] ^ res2d[j][t];
					}
					for (int t=0; t<49; t++) {
						cnt1 += xor_res[t];
					}
					
					if(cnt1<=1 || cnt1 >= 48){
						printf("tar = %d,success!\n",tar);
						for (int t=0; t<49; t++) {
							printf("%3d,",res2d[i][t]);
							if((t+1)%7==0)
								printf("\n");
						}
						printf("\n");
						for (int t=0; t<49; t++) {
							printf("%3d,",res2d[j][t]);
							if((t+1)%7==0)
								printf("\n");
						}
						printf("\n");
						twinf[tar].idx1s.push_back(i);
						twinf[tar].idx2s.push_back(j);
					}

				}
			}
		}
	}
	
	for(int i=0;i<49;i++){
		printf("%d find %d temp\n",i,twinf[i].idx1s.size());
	}

	//int start1=3,start2=3;

	for(int start1=0;start1<7;start1++){
		for(int start2=0;start2<7;start2++){

			int have_found[7*7] = {0};
			int have_found_cnt = 0;
			printf("start1=%d,start2=%d\n",start1,start2);
			printf("tw=%d.\n",twinf[POS(start1, start2)].idx1s.size());
			//choices3.clear();
			for(int i=0;i<1;i++){
				choices4.clear();
				int idx_str_idx1 = twinf[POS(start1, start2)].idx1s[i];
				int idx_str_idx2 = twinf[POS(start1, start2)].idx2s[i];
				string idx_str1 = uintarr2str(res2d[idx_str_idx1]);
				string idx_str2 = uintarr2str(res2d[idx_str_idx2]);
				ct_infos merged_uv;
				for(int j=0;j<choices[idx_str1].size();j++){
					merged_uv.push_back(choices[idx_str1][j]);
				}
				for(int j=0;j<choices[idx_str2].size();j++){
					merged_uv.push_back(choices[idx_str2][j]);
				}
				//printf("debug:mergedsize = %d\n",merged_uv.size());
				for(int t=0;t<merged_uv.size();t++){
					
					int c1=merged_uv[t].c1;
					int c2=merged_uv[t].c2;
					for(int c3=0;c3<86;c3++){
						for(int c4=0;c4<86;c4++){
							if(c1+c2+c3+c4>=86)
								continue;
							
							int choose_u1 = (int)(KYBER_Q*c1/1024.0 + 0.5);
							int choose_u2 = (int)(KYBER_Q*c2/1024.0 + 0.5);
							int choose_u3 = (int)(KYBER_Q*c3/1024.0 + 0.5);
							int choose_u4 = (int)(KYBER_Q*c4/1024.0 + 0.5);
							uint8_t tmp_result[7*7*7*7];
							for(int i1=0;i1<7;i1++){
								for(int i2=0;i2<7;i2++){
									for(int i3=0;i3<7;i3++){
										for(int i4=0;i4<7;i4++){
											float tmp = (2.0/KYBER_Q * ((int)(KYBER_Q/16.0*merged_uv[t].v + 0.5) - (cof_512[i1] * choose_u1 + cof_512[i2] * choose_u2 + cof_512[i3] * choose_u3 + cof_512[i4] * choose_u4)));
											int rst;
											if(tmp > 0)
												tmp_result[POS4(i1, i2, i3, i4)] = (int)(tmp+0.5) & 1;
											else
												tmp_result[POS4(i1, i2, i3, i4)] = (int)(tmp-0.5) & 1;
										}
									}
								}
							}
							ct_info4 nf = {c1,c2,c3,c4,merged_uv[t].v};
							string formed_str = uintarr2str4(tmp_result);
							if(choices4.find(formed_str) == end(choices4)){
								ct_infos4 v;
								v.push_back(nf);
								choices4.insert(make_pair(uintarr2str4(tmp_result),v));
							}
							else{
								choices4[formed_str].push_back(nf);
							}

						}
					}
					
				}
				
				
				

					
					int map_size4 = choices4.size();
					printf("sz=%d\n",map_size4);
					//printf("choice4_sz=%d\n",choices4.size());
					auto res4d = new uint8_t[map_size4][49*7*7];
					int ccnt4 = 0;
					for(auto x4:choices4){
						str2uint4(x4.first, res4d[ccnt4++]);
					}
					for(int tar1=0;tar1<7;tar1++){
						for(int tar2=0;tar2<7;tar2++){
							if(check_already(3, 3, tar1, tar2) == 1)
								continue;
							for(int rr=200;rr<map_size4;rr+=200){
								for(int i=rr-200;i<rr;i++){
									for(int j=i+1;j<rr;j++){
										int d1 = res4d[i][POS4(3,3,tar1,tar2)];
										int d2 = res4d[j][POS4(3,3,tar1,tar2)];
										int fail=0;
										for(int k=0;k<49*7*7;k++){
											if(k==POS4(3,3,tar1,tar2))
												continue;
											if(res4d[i][k] == d1 && res4d[j][k] == d2){
												fail = 1;
												break;
											}
										}
										if(fail != 1){
											printf("tar1 = %d, tar2= %d,success!\n",tar1,tar2);
											have_found[tar1 + tar2*7] = 1;
											have_found_cnt++;
											printf("signal:%d,%d\n",d1,d2);
											ct_infos4 d1info = choices4[uintarr2str4(res4d[i])];
											ct_infos4 d2info = choices4[uintarr2str4(res4d[j])];
											append_res(3, 3, tar1, tar2, d1info[0], d1, d2info[0], d2);
											printf("c11=%d,c21=%d,c31=%d,c41=%d,v1=%d\n",d1info[0].c1,d1info[0].c2,d1info[0].c3,d1info[0].c4,d1info[0].v);
											printf("c12=%d,c22=%d,c32=%d,c42=%d,v2=%d\n",d2info[0].c1,d2info[0].c2,d2info[0].c3,d2info[0].c4,d2info[0].v);
											//													if(have_found_cnt == 24)
											//														goto find_next_pair;
											if(total == 49*49)
												goto all_ok;
											goto there;
										}
									}
								}
							}
							there: continue;
						}
					}
					delete[] res4d;
					choices4.clear();

				

			}
//			find_next_pair: 
//				continue;
		}
	}
all_ok:
	for(int i1=0;i1<7;i1++){
		for(int i2=0;i2<7;i2++){
			for(int i3=0;i3<7;i3++){
				for(int i4=0;i4<7;i4++){
					idf tmp = final_result[POS4(i1, i2, i3, i4)];
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
	
	
	printf("sz=%d\n",choices.size());
}