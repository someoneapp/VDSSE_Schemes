#ifndef _AES_CTR_H_
#define _AES_CTR_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _e_ctx e_ctx;

e_ctx* e_allocate  (void *misc);  /* Allocate ae_ctx, set optional ptr   */
void    e_free      (e_ctx *ctx); /* Deallocate ae_ctx struct            */
int     e_clear     (e_ctx *ctx); /* Undo initialization                 */

int e_init(e_ctx     *ctx,
            const void *key,
            int         key_len);

int fencrypt1(e_ctx     *ctx,
               const void *nonce,
               const void *pt,
               int         pt_len, 
               void       *ct);

int encrypt_ctr(e_ctx     *ctx,
               const void *nonce,
               const void *pt,
               int         pt_len,
               void       *ct);


int decrypt_ctr(e_ctx     *ctx,
               const void *nonce,
               const void *ct,
               int ct_len,
               void       *pt);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif /* _AE_H_ */