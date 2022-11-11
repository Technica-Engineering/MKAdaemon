/*
 * Wrapper functions for OpenSSL libcrypto
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "mka_private.h"
#include "mka_crypto.h"
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>


static int openssl_digest_vector(const EVP_MD *type, size_t num_elem,
				 const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	// Technica: relevant for Macsec-PSK
	EVP_MD_CTX *ctx;
	size_t i;
	unsigned int mac_len;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;
	if (!EVP_DigestInit_ex(ctx, type, NULL)) {
		printf("OpenSSL: EVP_DigestInit_ex failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	for (i = 0; i < num_elem; i++) {
		if (!EVP_DigestUpdate(ctx, addr[i], len[i])) {
			printf("OpenSSL: EVP_DigestUpdate "
				   "failed: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			EVP_MD_CTX_free(ctx);
			return -1;
		}
	}
	if (!EVP_DigestFinal(ctx, mac, &mac_len)) {
		printf("OpenSSL: EVP_DigestFinal failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	EVP_MD_CTX_free(ctx);

	return 0;
}


int32_t sha1_vector(size_t num_elem, const uint8_t *const addr[], const size_t *len, uint8_t *mac)
{
	return openssl_digest_vector(EVP_sha1(), num_elem, (uint8_t const**)addr, len, mac);
}


static const EVP_CIPHER * aes_get_evp_cipher(size_t keylen)
{
	switch (keylen) {
	case 16:
		return EVP_aes_128_ecb();
	case 24:
		return EVP_aes_192_ecb();
	case 32:
		return EVP_aes_256_ecb();
	}

	return NULL;
}


void * aes_encrypt_init(const uint8_t *key, size_t len)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *type;

	type = aes_get_evp_cipher(len);
	if (!type) {
		printf("%s: Unsupported len=%u",
			   __func__, (unsigned int) len);
		return NULL;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return NULL;
	if (EVP_EncryptInit_ex(ctx, type, NULL, key, NULL) != 1) {
		os_free(ctx);
		return NULL;
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	return ctx;
}


int32_t aes_encrypt(void *ctx, const uint8_t *plain, uint8_t *crypt)
{
	EVP_CIPHER_CTX *c = ctx;
	int clen = 16;
	if (EVP_EncryptUpdate(c, crypt, &clen, plain, 16) != 1) {
		printf("OpenSSL: EVP_EncryptUpdate failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return 0;
}


void aes_encrypt_deinit(void *ctx)
{
	EVP_CIPHER_CTX *c = ctx;
	uint8_t buf[16];
	int len = sizeof(buf);
	if (EVP_EncryptFinal_ex(c, buf, &len) != 1) {
		printf("OpenSSL: EVP_EncryptFinal_ex failed: "
			   "%s", ERR_error_string(ERR_get_error(), NULL));
	}
	if (len != 0) {
		printf("OpenSSL: Unexpected padding length %d "
			   "in AES encrypt", len);
	}
	EVP_CIPHER_CTX_free(c);
}


#ifndef CONFIG_OPENSSL_INTERNAL_AES_WRAP

int32_t aes_wrap(const uint8_t *kek, size_t kek_len, uint32_t n, const uint8_t *plain, uint8_t *cipher)
{
	AES_KEY actx;
	int res;

	if (AES_set_encrypt_key(kek, kek_len << 3, &actx))
		return -1;
	res = AES_wrap_key(&actx, NULL, cipher, plain, n * 8);
	OPENSSL_cleanse(&actx, sizeof(actx));
	return res <= 0 ? -1 : 0;
}


int32_t aes_unwrap(const uint8_t *kek, size_t kek_len, uint32_t n, const uint8_t *cipher,
	       uint8_t *plain)
{
	AES_KEY actx;
	int res;

	if (AES_set_decrypt_key(kek, kek_len << 3, &actx))
		return -1;
	res = AES_unwrap_key(&actx, NULL, plain, cipher, (n + 1) * 8);
	OPENSSL_cleanse(&actx, sizeof(actx));
	return res <= 0 ? -1 : 0;
}

#endif /* CONFIG_OPENSSL_INTERNAL_AES_WRAP */


#if 0 // Unused for now
static int openssl_hmac_vector(const EVP_MD *type, const uint8_t *key,
			       size_t key_len, size_t num_elem,
			       const uint8_t *addr[], const size_t *len, uint8_t *mac,
			       unsigned int mdlen)
{
	HMAC_CTX *ctx;
	size_t i;
	int res;

	ctx = HMAC_CTX_new();
	if (!ctx)
		return -1;
	res = HMAC_Init_ex(ctx, key, key_len, type, NULL);
	if (res != 1)
		goto done;

	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	res = HMAC_Final(ctx, mac, &mdlen);
done:
	HMAC_CTX_free(ctx);

	return res == 1 ? 0 : -1;
}


int32_t hmac_sha1_vector(const uint8_t *key, size_t key_len, size_t num_elem,
		     const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	return openssl_hmac_vector(EVP_sha1(), key, key_len, num_elem, addr,
				   len, mac, 20);
}
#endif

bool MKA_GetRandomBytes(uint32_t size, uint8_t* bytes)
{
    FILE* urandom = fopen("/dev/urandom", "rb");
    bool result;

    if (NULL == urandom) {
        MKA_LOG_ERROR("Cannot obtain random numbers from /dev/urandom!");
        result = false;
    }
    else {
        result = fread(bytes, size, 1, urandom);
        (void)fclose(urandom);
    }

    return result;
}

