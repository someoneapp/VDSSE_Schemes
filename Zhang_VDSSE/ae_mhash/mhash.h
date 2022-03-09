

#ifndef _MHASH_H_
#define _MHASH_H_

#ifdef __cplusplus
extern "C" {
#endif


#define MHASH_SUCCESS       ( 0)
#define MHASH_FAILED       (-1)



typedef struct _mhash_ctx mhash_ctx;



mhash_ctx* mhash_allocate  (void *misc);  
void    mhash_free      (mhash_ctx *ctx);
int     mhash_clear     (mhash_ctx *ctx);
int     mhash_ctx_sizeof(void);       


int mhash_init(mhash_ctx     *ctx,
            const void *key,
            int         key_len);


int mhash_xor(mhash_ctx     *  ctx,
               const void *e,
               int         e_len,
               void       *hash);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif
