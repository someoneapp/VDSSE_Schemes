

/* MAX_KEY_BYTES specifies the maximum size key you intend to supply OCB, and
/  *must* be 16, 24, or 32. In *some* AES implementations it is possible to
/  limit internal key-schedule sizes, so keep this as small as possible.   */
#define MAX_KEY_BYTES             16

/* To eliminate the use of vector types, set the following non-zero        */
#define VECTORS_OFF                0

/* ----------------------------------------------------------------------- */
/* Derived configuration options - Adjust as needed                        */
/* ----------------------------------------------------------------------- */

/* These determine whether vectors should be used.                         */
#define USE_SSE2    ((__SSE2__ || (_M_IX86_FP>=2) || _M_X64) && !VECTORS_OFF)
#define USE_ALTIVEC (__ALTIVEC__ && !VECTORS_OFF)

/* ----------------------------------------------------------------------- */
/* Includes and compiler specific definitions                              */
/* ----------------------------------------------------------------------- */

#include "aes_ctr.h"
#include <stdlib.h>
#include <string.h>
//#include <openssl/aes.h> 

/* Define standard sized integers                                          */
#if defined(_MSC_VER) && (_MSC_VER < 1600)
	typedef unsigned __int8  uint8_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;
	typedef          __int64 int64_t;
#else
	#include <stdint.h>
#endif

/* How to force specific alignment, request inline, restrict pointers      */
#if __GNUC__
	#define ALIGN(n) __attribute__ ((aligned(n)))
	#define inline __inline__
	#define restrict __restrict__
#elif _MSC_VER
	#define ALIGN(n) __declspec(align(n))
	#define inline __inline
	#define restrict __restrict
#elif __STDC_VERSION__ >= 199901L   /* C99: delete align, keep others      */
	#define ALIGN(n)
#else /* Not GNU/Microsoft/C99: delete alignment/inline/restrict uses.     */
	#define ALIGN(n)
	#define inline
	#define restrict
#endif

/* How to endian reverse a uint64_t                                        */
#if _MSC_VER
    #define bswap64(x) _byteswap_uint64(x)
#elif (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 3)) && !__arm__
    #define bswap64(x) __builtin_bswap64(x)
#elif __GNUC__ && __amd64__
    #define bswap64(x) ({uint64_t y=x;__asm__("bswapq %0":"+r"(y));y;})
#else

/* Build bswap64 out of two bswap32's                                      */
#if __GNUC__ && (__ARM_ARCH_6__ || __ARM_ARCH_6J__ || __ARM_ARCH_6K__ ||    \
    __ARM_ARCH_6Z__ || __ARM_ARCH_6ZK__ || __ARM_ARCH_6T2__ ||              \
    __ARM_ARCH_7__ || __ARM_ARCH_7A__ || __ARM_ARCH_7R__ || __ARM_ARCH_7M__)
	#define bswap32(x) ({uint32_t y; __asm__("rev %0, %1":"=r"(y):"r"(x));y;})
#elif __GNUC__ && __arm__
	#define bswap32(x)                             \
		({uint32_t t,y;                            \
		__asm__("eor     %1, %2, %2, ror #16\n\t" \
				"bic     %1, %1, #0x00FF0000\n\t" \
				"mov     %0, %2, ror #8\n\t"      \
				"eor     %0, %0, %1, lsr #8"      \
				: "=r"(y), "=&r"(t) : "r"(x));y;})
#elif __GNUC__ && __i386__
	#define bswap32(x) ({uint64_t y=x;__asm__("bswap %0":"+r"(y));y;})
#else        /* Some compilers recognize the following pattern */
	#define bswap32(x)                         \
	   ((((x) & 0xff000000u) >> 24) | \
		(((x) & 0x00ff0000u) >>  8) | \
		(((x) & 0x0000ff00u) <<  8) | \
		(((x) & 0x000000ffu) << 24))
#endif

static inline uint64_t bswap64(uint64_t x) {
	union { uint64_t ll; uint32_t l[2]; } w, r;
	w.ll = x;
	r.l[0] = bswap32(w.l[1]);
	r.l[1] = bswap32(w.l[0]);
	return r.ll;
}

#endif

#if _MSC_VER
    #define bswap32(x) _byteswap_uint(x)
#elif (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 3)) && !__arm__
    #define bswap32(x) ((uint32_t)__builtin_bswap32((int32_t)(x)))
#elif __GNUC__ && (__ARM_ARCH_6__ || __ARM_ARCH_6J__ || __ARM_ARCH_6K__ ||    \
    __ARM_ARCH_6Z__ || __ARM_ARCH_6ZK__ || __ARM_ARCH_6T2__ ||              \
    __ARM_ARCH_7__ || __ARM_ARCH_7A__ || __ARM_ARCH_7R__ || __ARM_ARCH_7M__)
	#define bswap32(x) ({uint32_t y; __asm__("rev %0, %1":"=r"(y):"r"(x));y;})
#elif __GNUC__ && __arm__
	#define bswap32(x)                             \
		({uint32_t t,y;                            \
		__asm__("eor     %1, %2, %2, ror #16\n\t" \
				"bic     %1, %1, #0x00FF0000\n\t" \
				"mov     %0, %2, ror #8\n\t"      \
				"eor     %0, %0, %1, lsr #8"      \
				: "=r"(y), "=&r"(t) : "r"(x));y;})
#elif __GNUC__ && __i386__
	#define bswap32(x) ({uint64_t y=x;__asm__("bswap %0":"+r"(y));y;})
#else        /* Some compilers recognize the following pattern */
	#define bswap32(x)                         \
	   ((((x) & UINT32_C(0xff000000)) >> 24) | \
		(((x) & UINT32_C(0x00ff0000)) >>  8) | \
		(((x) & UINT32_C(0x0000ff00)) <<  8) | \
		(((x) & UINT32_C(0x000000ff)) << 24))
#endif

static inline uint32_t bswap32_if_le(uint32_t x)
{
	const union { unsigned x; unsigned char endian; } little = { 1 };
	return (little.endian?bswap32(x):x);
}

/* ----------------------------------------------------------------------- */
/* Define blocks and operationss -- Patch if incorrect on your compiler.   */
/* ----------------------------------------------------------------------- */

#if USE_SSE2
    #include <xmmintrin.h>        /* SSE instructions and _mm_malloc */
    #include <emmintrin.h>        /* SSE2 instructions               */
    typedef ALIGN(16) __m128i block;
    #define add_one(b)            _mm_add_epi32(b,_mm_set_epi32(1,0,0,0))
    #define xor_block(x, y)       _mm_xor_si128(x,y)
    #define zero_block()          _mm_setzero_si128()
    #define unequal_blocks(x, y) \
    					   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
	#if __SSSE3__
    #include <tmmintrin.h>        /* SSSE3 instructions              */
    #define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))
	#else
    static inline block swap_if_le(block b) {
		block a = _mm_shuffle_epi32  (b, _MM_SHUFFLE(0,1,2,3));
		a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(2,3,0,1));
		a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(2,3,0,1));
		return _mm_xor_si128(_mm_srli_epi16(a,8), _mm_slli_epi16(a,8));
    }
	#endif
#elif USE_ALTIVEC
    #include <altivec.h>
    typedef ALIGN(16) vector unsigned block;
    static inline block add_one(block b) {const vector unsigned int one = {0,0,0,1}; return vec_add(b,one);}
    #define xor_block(x,y)        vec_xor(x,y)
    #define zero_block()          vec_splat_u32(0)
    #define unequal_blocks(x,y)   vec_any_ne(x,y)
    #define swap_if_le(b)         (b)
#else
    typedef struct { uint64_t l,r; } block;
    static block add_one(block x)                         {x.r+=1; return x;}
    static block xor_block(block x, block y)  {x.l^=y.l; x.r^=y.r; return x;}
    static block zero_block(void)        { const block t = {0,0}; return t; }
    #define unequal_blocks(x, y)         ((((x).l^(y).l)|((x).r^(y).r)) != 0)
    static inline block swap_if_le(block b) {
		const union { unsigned x; unsigned char endian; } little = { 1 };
    	if (little.endian) {
			block a;
			a.l = bswap64(b.l);
			a.r = bswap64(b.r);
			return a;
    	} else
    		return b;
    }
#endif

/* Sometimes it is useful to view a block as an array of other types.
/  Doing so is technically undefined, but well supported in compilers.     */
typedef union {
	uint64_t u64[2]; uint32_t u32[4]; uint8_t u8[16]; block bl;
} block_multiview;

/* ----------------------------------------------------------------------- */
/* AES - Code uses OpenSSL API. Other implementations get mapped to it.    */
/* ----------------------------------------------------------------------- */

#include <openssl/aes.h>                            /* http://openssl.org/ */
#include <wmmintrin.h>
#include "aesni-openssl.h"

#define AES_set_encrypt_key aesni_set_encrypt_key
#define AES_set_decrypt_key aesni_set_decrypt_key
#define AES_encrypt         aesni_encrypt
#define AES_decrypt         aesni_decrypt

struct _e_ctx {
    AES_KEY encrypt_key;
};

/* ----------------------------------------------------------------------- */

int e_init(e_ctx *ctx, const void *key, int key_len)
{
    /* Initialize encryption & decryption keys */
    AES_set_encrypt_key((unsigned char *)key, key_len*8, &ctx->encrypt_key);
    return 1;
}


//#include "aesni-openssl.h"

int fencrypt1(e_ctx     * restrict ctx,
               const void * restrict nonce,
               const void *pt,
               int         pt_len,
               void       *ct)
{
	#if SAFE_OUTPUT_BUFFERS
	aesni_ctr32_encrypt_blocks(pt,ct,(pt_len+15)/16,&ctx->encrypt_key,nonce);
	#else
    union { unsigned char u8[16]; uint32_t u32[4]; block bl; } ctr;
	if (pt_len <=16){
		ctr.bl = zero_block();
		memcpy(ctr.u8, pt, pt_len);
		//tmp.u8[pt_len] = (unsigned char)0x80u;
		aesni_ctr32_encrypt_blocks(ctr.u8,ct,1,&ctx->encrypt_key,nonce);
	} else{
		char *tmp;
		aesni_ctr32_encrypt_blocks(pt,tmp,pt_len/16,&ctx->encrypt_key,nonce);
		memcpy(ct,tmp,16);
	}
	#endif
    return (int) pt_len;
}

int decrypt_ctr(e_ctx     *ctx,
               const void *nonce,
               const void *ct,
               int         ct_len,
               void       *pt)
{
	#if SAFE_OUTPUT_BUFFERS
	aesni_ctr32_encrypt_blocks(ct,pt,(ct_len+15)/16,&ctx->encrypt_key,nonce);
	#else
    union { unsigned char u8[16]; uint32_t u32[4]; block bl; } ctr;
    unsigned remaining;
	if (ct_len>=16){
		aesni_ctr32_encrypt_blocks(ct,pt,ct_len/16,&ctx->encrypt_key,nonce);
	}
	remaining = ct_len % 16;
	if (remaining) {
		ctr.bl = *(block *)nonce;
		ctr.u32[3] += ct_len/16;
		aesni_encrypt(ctr.u8,ctr.u8,&ctx->encrypt_key);
		ctr.bl = xor_block(ctr.bl,((block *)ct)[ct_len/16]);
		
		//ctr.bl = xor_block(ctr.bl,((block *)ct)[ct_len/16]);
		//aesni_decrypt(ctr.u8,ctr.u8,&ctx->encrypt_key);
		//ctr.u32[3] += ct_len/16;
		//ctr.bl = xor_block(ctr.bl,((block *)ct)[ct_len/16]);
		memcpy((block *)pt+(ct_len/16),ctr.u8,remaining);
	}
	#endif
    return (int) ct_len;

}

			   









/* ----------------------------------------------------------------------- */
/* Public functions                                                        */
/* ----------------------------------------------------------------------- */

/* Some systems do not 16-byte-align dynamic allocations involving 16-byte
/  vectors. Adjust the following if your system is one of these            */

/* These determine how to allocate 16-byte aligned vectors, if needed.     */
#define USE_MM_MALLOC      (USE_SSE2 && !(_M_X64 || __amd64__))
#define USE_POSIX_MEMALIGN (USE_ALTIVEC && __GLIBC__ && !__PPC64__)

e_ctx* e_allocate(void *misc)
{ 
	void *p;
	(void) misc;                     /* misc unused in this implementation */
	#if USE_MM_MALLOC
    	p = _mm_malloc(sizeof(e_ctx),16); 
	#elif USE_POSIX_MEMALIGN
		if (posix_memalign(&p,16,sizeof(e_ctx)) != 0) p = NULL;
	#else
		p = malloc(sizeof(e_ctx)); 
	#endif
	return (e_ctx *)p;
}

void e_free(e_ctx *ctx)
{
	#if USE_MM_MALLOC
		_mm_free(ctx);
	#else
		free(ctx);
	#endif
}

int e_clear (e_ctx *ctx) /* Zero ae_ctx and undo initialization          */
{
	memset(ctx, 0, sizeof(e_ctx));
	return 1;
}

int e_ctx_sizeof(void) { return (int) sizeof(e_ctx); }


