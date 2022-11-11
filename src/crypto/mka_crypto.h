/*
 * Wrapper functions for crypto libraries
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file defines the cryptographic functions that need to be implemented
 * for wpa_supplicant and hostapd. When TLS is not used, internal
 * implementation of MD5, SHA1, and AES is used and no external libraries are
 * required. When TLS is enabled (e.g., by enabling EAP-TLS or EAP-PEAP), the
 * crypto library used by the TLS implementation is expected to be used for
 * non-TLS needs, too, in order to save space by not implementing these
 * functions twice.
 *
 * Wrapper code for using each crypto library is in its own file (crypto*.c)
 * and one of these files is build and linked in to provide the functions
 * defined here.
 */

#ifndef MKA_CRYPTO_H
#define MKA_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE          16U

/**
 * sha1_vector - SHA-1 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 on failure
 */
int32_t sha1_vector(size_t num_elem, const uint8_t *const addr[], const size_t *len, uint8_t *mac);


/**
 * aes_encrypt_init - Initialize AES for encryption
 * @key: Encryption key
 * @len: Key length in bytes (usually 16, i.e., 128 bits)
 * Returns: Pointer to context data or %NULL on failure
 */
void * aes_encrypt_init(const uint8_t *key, size_t len);

/**
 * aes_encrypt - Encrypt one AES block
 * @ctx: Context pointer from aes_encrypt_init()
 * @plain: Plaintext data to be encrypted (16 bytes)
 * @crypt: Buffer for the encrypted data (16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int32_t aes_encrypt(void *ctx, const uint8_t *plain, uint8_t *crypt);

/**
 * aes_encrypt_deinit - Deinitialize AES encryption
 * @ctx: Context pointer from aes_encrypt_init()
 */
void aes_encrypt_deinit(void *ctx);

/**
 * aes_decrypt_init - Initialize AES for decryption
 * @key: Decryption key
 * @len: Key length in bytes (usually 16, i.e., 128 bits)
 * Returns: Pointer to context data or %NULL on failure
 */
void * aes_decrypt_init(const uint8_t *key, size_t len);

/**
 * aes_decrypt - Decrypt one AES block
 * @ctx: Context pointer from aes_encrypt_init()
 * @crypt: Encrypted data (16 bytes)
 * @plain: Buffer for the decrypted data (16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int32_t aes_decrypt(void *ctx, const uint8_t *crypt, uint8_t *plain);

/**
 * ieee8021x_aes_kdf - Key derivation function
 * Returns: 0 on success, -1 on failure
 */
bool ieee8021x_aes_kdf(const uint8_t *key, size_t key_len,
		   const uint8_t *label, uint32_t label_len,
            const uint8_t *context, uint32_t ctx_len,
            uint32_t ret_len, uint8_t *ret);

/**
 * ieee802.1X derivation of KEK from CAK
 * @param[in] cak       CAK key
 * @param[in] ckn       Cak Key Name
 * @param[in] kek_len   Length of KEK to generate
 * @param[out] kek      Output key
 * Returns: true on success, false on failure
 */
bool MKA_DeriveKEK(t_MKA_key const* cak, t_MKA_ckn const* ckn,
            uint32_t kek_len, t_MKA_key* kek);

/**
 * ieee802.1X derivation of ICK from CAK
 * @param[in] aa        Algorithm Agility
 * @param[in] cak       CAK key
 * @param[in] ckn       Cak Key Name
 * @param[in] ick_len   Length of ICK to generate
 * @param[out] ick      Output key
 * Returns: true on success, false on failure
 */
bool MKA_DeriveICK(uint32_t aa, t_MKA_key const* cak, t_MKA_ckn const* ckn,
            uint32_t ick_len, t_MKA_key* ick);

/**
 * ieee802.1X derivation of SAK (optional? IEEE802.1X allows SAK to be just a random number)
 * @remark: Assuming peer to peer implementation, only two MI are going to be used.
 * @param[in] cak       CAK key
 * @param[in] ks_nonce  Random input of size "key_len"
 * @param[in] mi_local  First MI to use in computation (MKA_MI_LENGTH)
 * @param[in] mi_peer   Second MI to use in computation (MKA_MI_LENGTH)
 * @param[in] kn        Key number
 * @param[in] out_len   Length of the output key
 * @param[out] sak      Derived output key SAK
 * Returns: true on success, false on failure
 */
bool MKA_DeriveSAK(t_MKA_key const* cak, uint8_t const*ks_nonce,
    uint8_t const* mi_local, uint8_t const* mi_peer, uint32_t kn,
    uint32_t out_len, t_MKA_key *sak);

/**
 * ieee802.1X ICV computation
 * @param[in] aa        Algorithm Agility
 * @param[in] ick       ICK key for computation
 * @param[in] message   Message input for ICV computation
 * @param[in] msg_len   Length of the message
 * @param[out] icv      Output ICV
 * Returns: true on success, false on failure
 */
bool MKA_ComputeICV(uint32_t aa, t_MKA_key const* ick,
                uint8_t const*message, uint32_t msg_len, uint8_t *icv);

/**
 * ieee802.1X Key wrapping
 * @param[in] kek           KEK wrapping key
 * @param[in] input_key     Input key
 * @param[out] out_wrapped  Output wrapped key, same size than input key
 * Returns: true on success, false on failure
 */
bool MKA_WrapKey(t_MKA_key const*kek, t_MKA_key const*input_key,
                uint8_t*output_wrapped);

/**
 * ieee802.1X Key unwrapping
 * @param[in] kek           KEK wrapping key
 * @param[in] in_wrapped    Incoming wrapped key
 * @param[in] len           Size of wrapped key in bytes
 * @param[out] output_key   Output key
 * Returns: true on success, false on failure
 */
bool MKA_UnwrapKey(t_MKA_key const*kek, uint8_t const*in_wrapped,
                uint32_t len, t_MKA_key *output_key);

/**
 * Random numbers
 * @param[in] size          Number of random bytes to generate
 * @param[out] bytes        Random bytes
 * Returns: true on success, false on failure
 */
bool MKA_GetRandomBytes(uint32_t size, uint8_t* bytes);

/**
 * Generate a random key of given size
 * @param[in] size          Size of the key
 * @param[out] key          Randomly generated key
 * Returns: true on success, false on failure
 */
bool MKA_CreateRandomKey(uint32_t size, t_MKA_key* key);

/**
 * aes_decrypt_deinit - Deinitialize AES decryption
 * @ctx: Context pointer from aes_encrypt_init()
 */
void aes_decrypt_deinit(void *ctx);


/**
 * crypto_global_init - Initialize crypto wrapper
 *
 * This function is only used with internal TLSv1 implementation
 * (CONFIG_TLS=internal). If that is not used, the crypto wrapper does not need
 * to implement this.
 */
int32_t crypto_global_init(void);

/**
 * crypto_global_deinit - Deinitialize crypto wrapper
 *
 * This function is only used with internal TLSv1 implementation
 * (CONFIG_TLS=internal). If that is not used, the crypto wrapper does not need
 * to implement this.
 */
void crypto_global_deinit(void);

int32_t aes_wrap(const uint8_t *kek, size_t kek_len, uint32_t n, const uint8_t *plain,
			  uint8_t *cipher);
int32_t aes_unwrap(const uint8_t *kek, size_t kek_len, uint32_t n,
			    const uint8_t *cipher, uint8_t *plain);
int32_t omac1_aes_vector(const uint8_t *key, size_t key_len,
				  size_t num_elem, const uint8_t *addr[],
				  const size_t *len, uint8_t *mac);
int32_t omac1_aes_128_vector(const uint8_t *key, size_t num_elem,
				      const uint8_t *addr[], const size_t *len,
				      uint8_t *mac);
int32_t omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len,
			       uint8_t *mac);
int32_t omac1_aes_256(const uint8_t *key, const uint8_t *data, size_t data_len,
			       uint8_t *mac);

/**
 * crypto_get_random - Get random number function
 * @data: Pointer to store random generated data.
 * @data_len: Length of the desired random data.
 * Returns: 0 on success, -1 on failure
 */
int32_t crypto_get_random(uint8_t * const data, const uint32_t data_len);

#ifdef __cplusplus
}
#endif


#endif /* MKA_CRYPTO_H */
