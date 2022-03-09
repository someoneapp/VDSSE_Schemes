#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "ae.h"
#include "mhash.h"
#include <sys/time.h>

//#include <openssl/sha.h>
//#include <openssl/crypto.h>

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

extern char infoString[];  /* Each AE implementation must have a global one */

#ifndef MAX_ITER
#define MAX_ITER 1024
#endif

/*static char *pt(unsigned char *md, int len)
{
	int i;
	static char buf[256];

	for (i = 0; i < len; i++)
		sprintf(&(buf[i * 2]), "%02x", md[i]);
	return (buf);
}

void sha1(const void *ad, int ad_len, void *hash)
{
	SHA_CTX c;
	unsigned char md[SHA_DIGEST_LENGTH];
	//char *p;

	SHA1((unsigned char *)ad, ad_len, md);
	//p = pt(md, SHA_DIGEST_LENGTH);
	//printf("SHA1	: %s\n", p);

	SHA1_Init(&c);
	SHA1_Update(&c, ad, ad_len);
	SHA1_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	//p = pt(md, SHA_DIGEST_LENGTH);
	//printf("SHA1	: %s\n", p);
	*(char *)hash = md;
}

void sha256(const void *ad, int ad_len, void *hash)
{
	SHA256_CTX c;
	unsigned char md[SHA256_DIGEST_LENGTH];
	//char *p;

	SHA256((unsigned char *)ad, ad_len, md);
	//p = pt(md, SHA256_DIGEST_LENGTH);

	SHA256_Init(&c);
	SHA256_Update(&c, ad, ad_len);
	SHA256_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	//printf("md: %s\n", md);
	//p = pt(md, SHA256_DIGEST_LENGTH);
	//printf("SHA256	: %s\n", p);
	*(char *)hash = md;
}*/

int main(int argc, char **argv)
{
	/* Allocate locals */
	ALIGN(16) char pt[8*1024] = {0};
	ALIGN(16) char ct[8*1024] = {0};
	//ALIGN(16) char tag[8];
	ALIGN(16) unsigned char key[] = "abcdefghijklmnop";
	//ALIGN(16) unsigned char nonce[16] = "0000000000000000";
	//ALIGN(16) int nonce2 = 7;
	char outbuf[MAX_ITER*15+1024];   // outbuf的长度为1024*15+1024
	int iter_list[2048]; /* Populate w/ test lengths, -1 terminated */
	ae_ctx* ctx = ae_allocate(NULL);
	mhash_ctx* m_ctx = mhash_allocate(NULL);
	char *outp = outbuf;
	int iters, i, j, len;
	double Hz,sec;
	double ipi=0, tmpd;
	clock_t c;
	struct timeval t1, t2;

	/* populate iter_list, terminate list with negative number */
	for (i=0; i<MAX_ITER; ++i)
		iter_list[i] = i+1;       //iter_list[0] = 1, iter_list[1] = 2, ..., iter_list[1023] = 1024
	if (MAX_ITER < 44) iter_list[i++] = 44;
	if (MAX_ITER < 552) iter_list[i++] = 552;
	if (MAX_ITER < 576) iter_list[i++] = 576;
	if (MAX_ITER < 1500) iter_list[i++] = 1500; // iter_list[1024] = 1500
	if (MAX_ITER < 4096) iter_list[i++] = 4096;
	iter_list[i] = -1;    // iter_list[1025] = -1

    /* Create file for writing data */
	FILE *fp = NULL;
    char str_time[25];
	time_t tmp_time = time(NULL);
	struct tm *tp = localtime(&tmp_time);
	strftime(str_time, sizeof(str_time), "%F %R", tp);
	if (argc > 2) {
		printf("Usage: %s [output_filename]\n", argv[0]);
		return 0;
	} else if (argc == 2){
		//Hz = 1e6 * strtol(argv[1], (char **)NULL, 10);
		//if (argc == 3
		fp = fopen(argv[1], "w");
	}
	
    outp += sprintf(outp, "%s ", infoString);
    #if __INTEL_COMPILER
        outp += sprintf(outp, "- Intel C %d.%d.%d ",
            (__ICC/100), ((__ICC/10)%10), (__ICC%10));
    #elif _MSC_VER
        outp += sprintf(outp, "- Microsoft C %d.%d ",
            (_MSC_VER/100), (_MSC_VER%100));
    #elif __clang_major__
        outp += sprintf(outp, "- Clang C %d.%d.%d ",
            __clang_major__, __clang_minor__, __clang_patchlevel__);
    #elif __clang__
        outp += sprintf(outp, "- Clang C 1.x ");
    #elif __GNUC__
        outp += sprintf(outp, "- GNU C %d.%d.%d ",
            __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    #endif

    #if __x86_64__ || _M_X64
    outp += sprintf(outp, "x86_64 ");
    #elif __i386__ || _M_IX86
    outp += sprintf(outp, "x86_32 ");
    #elif __ARM_ARCH_7__ || __ARM_ARCH_7A__ || __ARM_ARCH_7R__ || __ARM_ARCH_7M__
    outp += sprintf(outp, "ARMv7 ");
    #elif __ARM__ || __ARMEL__
    outp += sprintf(outp, "ARMv5 ");
    #elif __MIPS__ || __MIPSEL__
    outp += sprintf(outp, "MIPS32 ");
    #elif __ppc64__
    outp += sprintf(outp, "PPC64 ");Starting
    #elif __ppc__
    outp += sprintf(outp, "PPC32 ");
    #elif __sparc__
    outp += sprintf(outp, "SPARC ");
    #endif

    outp += sprintf(outp, "- Run %s\n\n",str_time);

	outp += sprintf(outp, "Context: %d bytes\n", ae_ctx_sizeof());

	printf("Starting run...\n");fflush(stdout); // 清空输出缓冲区，并把缓冲区内容输出
	ae_init(ctx, key, 16);
	printf("11111111111111111111111111111111111111111111111111\n");
	ALIGN(16) const char *test1  = "10171130101769161013830010181889101704641001457310173905";
	ALIGN(16) unsigned long c_test[7];
    ALIGN(16) unsigned long tag;
	int nonce2 =1;
	printf("2222222222222222222222222222222222222222222\n");
	ae_encrypt(ctx, &nonce2, test1, 56, c_test, &tag);
	printf("tag: %lu\n", tag);
	for (i=0; i<7; i++){
		printf("cipher: %lu\n", c_test[i]);
	}
	printf("tag: %lu\n", tag);
	ALIGN(16) char test2[56];
	ae_decrypt(ctx, &nonce2, c_test, 56, test2, &tag);
	for (i=0; i<56; i++){
		printf("%c", test2[i]);
	}
	printf("\n");
	return 1;
}
