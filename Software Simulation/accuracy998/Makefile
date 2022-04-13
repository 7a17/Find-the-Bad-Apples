all:
	/usr/bin/gcc -O3 -march=native -fomit-frame-pointer -o test_our_method cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c test_our_method.c reduce.c rng.c verify.c symmetric-shake.c -lcrypto
	/usr/bin/gcc -O3 -march=native -fomit-frame-pointer -o test_classical_vote cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c test_classical_vote.c reduce.c rng.c verify.c symmetric-shake.c -lcrypto
