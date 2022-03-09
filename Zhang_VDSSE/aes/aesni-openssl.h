
int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
			      AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
			      AES_KEY *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);

void aesni_ecb_encrypt(const unsigned char *in,
			   unsigned char *out,
			   size_t length,
			   const AES_KEY *key,
			   int enc);
void aesni_cbc_encrypt(const unsigned char *in,
			   unsigned char *out,
			   size_t length,
			   const AES_KEY *key,
			   unsigned char *ivec, int enc);

void aesni_ctr32_encrypt_blocks(const unsigned char *in,
			   unsigned char *out,
			   size_t blocks,
			   const AES_KEY *key,
			   const unsigned char *ivec);
/* Handles only complete blocks, operates on 32-bit counter and
 * does not update *ivec!
 */

void aesni_ccm64_encrypt_blocks (const void *in, void *out,
                        size_t blocks, const AES_KEY *key,
                        const char *ivec,char *cmac);
void aesni_ccm64_decrypt_blocks (const void *in, void *out,
                        size_t blocks, const AES_KEY *key,
                        const char *ivec,char *cmac);
/* Handles only complete blocks, operates on 64-bit counter and
 * does not update *ivec! Nor does it finalize CMAC value
 */
