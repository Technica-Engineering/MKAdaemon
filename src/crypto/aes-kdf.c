/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: aes-kdf.c
*
* © 2022 Technica Engineering GmbH.
*
* This program is free software: you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation, either version 2 of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this program. If not, see https://www.gnu.org/licenses/
*
******************************************************************************/

#include "mka_private.h"

/**
 * ieee802.1X key derivation function
 * @param[in] key       Input key
 * @param[in] key_len   Input key length (bytes, 16 or 32)
 * @param[in] label     Label for key derivation
 * @param[in] label_len Size of the label, in bytes
 * @param[in] context   Context for key derivation
 * @param[in] ctx_len   Size of the context, in bytes
 * @param[in] ret_len   Size of the output key to generate, in bytes.
 * @param[out] ret      Output key
 * Returns: true on success, false on failure
 */
bool ieee8021x_aes_kdf(const uint8_t *key, size_t key_len,
		   const uint8_t *label, uint32_t label_len,
            const uint8_t *context, uint32_t ctx_len,
            uint32_t ret_len, uint8_t *ret)
{
    bool result;

    // result not multiple of 128 bits (16 bytes)
    if (0U != (ret_len & 0xFU)) {
        result = false;

    } // 128 bit or 256 bit input keys
    else if ((MKA_KEY_128BIT != key_len) && (MKA_KEY_256BIT != key_len)) {
        result = false;

    }
    else {
        uint32_t const buf_len = label_len + ctx_len + 4U;
        // worst case:
        //  label_len = 12 (KEK, ICK, SAK)
        //  ctx_len = 16 (KEK, ICK), 60 (SAK)
        // total: 72 bytes, allocating 128
        uint8_t buf[128U];

        MKA_ASSERT(buf_len <= sizeof(buf), "Insufficient space for key derivation function");

        memcpy(&buf[1], label, label_len);
        buf[1U+label_len] = 0U;

        memcpy(&buf[2U+label_len], context, ctx_len);
        buf[2U+label_len+ctx_len] = (uint8_t)((ret_len >> 5) & 0xFFU);
        buf[3U+label_len+ctx_len] = (uint8_t)((ret_len << 3) & 0xFFU);

        result = true;

        uint32_t i;
        for(i=0U; (i<ret_len) && result; i += 16U) {
            buf[0] = 1U + (uint8_t)((i >> 4U) & 0xFFU);
            if (16U == key_len) {
                result = (0 == omac1_aes_128(key, buf, buf_len, &ret[i]));
            }
            else {
                result = (0 == omac1_aes_256(key, buf, buf_len, &ret[i]));
            }
        }
    }

    return result;
}

/**
 * ieee802.1X derivation of KEK from CAK
 * @param[in] cak       CAK key
 * @param[in] ckn       Cak Key Name
 * @param[in] kek_len   Length of KEK to generate
 * @param[out] kek      Output key
 * Returns: true on success, false on failure
 */
bool MKA_DeriveKEK(t_MKA_key const* cak, t_MKA_ckn const* ckn, uint32_t kek_len, t_MKA_key* kek)
{
    bool result;

    // Sanity check - null pointers
    if ((NULL == cak) || (NULL == ckn) || (NULL == kek)) {
        result = false;

    } // 128 or 256 bit supported for input key
    else if ((MKA_KEY_128BIT != cak->length) && (MKA_KEY_256BIT != cak->length)) {
        result = false;

    } // 128 or 256 bit supported for output key
    else if ((MKA_KEY_128BIT != kek_len) && (MKA_KEY_256BIT != kek_len)) {
        result = false;

    } //  Valid CKN
    else if ((ckn->length < MKA_CKN_MIN) || (ckn->length > MKA_CKN_MAX)) {
        result = false;

    } // Ok, do derive
    else {
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] essential type is different, but compliance with 802.1X is clearer
        static const uint8_t kek_derivation_label[] = {
            'I', 'E', 'E', 'E', '8', '0', '2', '1', ' ', 'K', 'E', 'K'
        };
        uint8_t context[16];
        memset(context, 0, sizeof(context));
        memcpy(context, ckn->name, MIN(sizeof(context), ckn->length));

        kek->length = (uint8_t)kek_len;
        result = ieee8021x_aes_kdf(
                /* kdk      */  cak->key,
                /* kdk_len  */  cak->length,
                /* label    */  kek_derivation_label,
                /* label_len*/  sizeof(kek_derivation_label),
                /* context  */  context,
                /* ctx len  */  sizeof(context),
                /* ret_bits */  kek_len,
                /* ret      */  kek->key
            );
    }

    return result;
}

/**
 * ieee802.1X derivation of ICK from CAK
 * @param[in] aa        Algorithm Agility
 * @param[in] cak       CAK key
 * @param[in] ckn       Cak Key Name
 * @param[in] ick_len   Length of ICK to generate
 * @param[out] ick      Output key
 * Returns: true on success, false on failure
 */
bool MKA_DeriveICK(uint32_t aa, t_MKA_key const* cak, t_MKA_ckn const* ckn, uint32_t ick_len, t_MKA_key* ick)
{
    bool result;

    // Sanity check - null pointers
    if ((NULL == cak) || (NULL == ckn) || (NULL == ick)) {
        result = false;

    } // 128 or 256 bit supported for input key
    else if ((MKA_KEY_128BIT != cak->length) && (MKA_KEY_256BIT != cak->length)) {
        result = false;

    } // 128 or 256 bit supported for output key
    else if ((MKA_KEY_128BIT != ick_len) && (MKA_KEY_256BIT != ick_len)) {
        result = false;

    } //  Valid CKN
    else if ((ckn->length < MKA_CKN_MIN) || (ckn->length > MKA_CKN_MAX)) {
        result = false;

    } // Ok, do derive
    else if (MKA_ALGORITHM_AGILITY == aa) {
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] essential type is different, but compliance with 802.1X is clearer
        static const uint8_t ick_derivation_label[] = {
            'I', 'E', 'E', 'E', '8', '0', '2', '1', ' ', 'I', 'C', 'K'
        };
        uint8_t context[16];
        memset(context, 0, sizeof(context));
        memcpy(context, ckn->name, MIN(sizeof(context), ckn->length));

        ick->length = (uint8_t)ick_len;
        result = ieee8021x_aes_kdf(
                /* kdk      */  cak->key,
                /* kdk_len  */  cak->length,
                /* label    */  ick_derivation_label,
                /* label_len*/  sizeof(ick_derivation_label),
                /* context  */  context,
                /* ctx len  */  sizeof(context),
                /* ret_bits */  ick_len,
                /* ret      */  ick->key
            );
    } // Algorithm Agility not implemented
    else {
        result = false;
    }

    return result;
}


/**
 * ieee802.1X derivation of SAK (optional? IEEE802.1X allows SAK to be just a random number)
 * @remark: Assuming peer to peer implementation, only two MI are going to be used.
 * @param[in] cak       CAK key
 * @param[in] ks_nonce  Random input of size "out_len"
 * @param[in] mi_local  First MI to use in computation (MKA_MI_LENGTH)
 * @param[in] mi_peer   Second MI to use in computation (MKA_MI_LENGTH)
 * @param[in] kn        Key number
 * @param[in] out_len   Length of the output key
 * @param[out] sak      Derived output key SAK
 * Returns: true on success, false on failure
 */
bool MKA_DeriveSAK(t_MKA_key const* cak, uint8_t const*ks_nonce,
    uint8_t const* mi_local, uint8_t const* mi_peer, uint32_t kn,
    uint32_t out_len, t_MKA_key *sak)
{
    bool result;

    // Sanity check - null pointers
    if ((NULL == cak) || (NULL == ks_nonce) || (NULL == mi_local) ||
                            (NULL == mi_peer) || (NULL == sak)) {
        result = false;

    } // 128 or 256 bit supported for input key
    else if ((MKA_KEY_128BIT != cak->length) && (MKA_KEY_256BIT != cak->length)) {
        result = false;

    } // 128 or 256 bit supported for output key
    else if ((MKA_KEY_128BIT != out_len) && (MKA_KEY_256BIT != out_len)) {
        result = false;
    }
    else {
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] essential type is different, but compliance with 802.1X is clearer
        static const uint8_t sak_derivation_label[] = {
            'I', 'E', 'E', 'E', '8', '0', '2', '1', ' ', 'S', 'A', 'K'
        };
        uint8_t context[MKA_KEY_MAX+MKA_MI_LENGTH+MKA_MI_LENGTH+sizeof(uint32_t)];
        uint32_t idx = 0U;
        memcpy(context, ks_nonce, out_len);
        idx += out_len;
        memcpy(&context[idx], mi_local, MKA_MI_LENGTH);
        idx += MKA_MI_LENGTH;
        memcpy(&context[idx], mi_peer, MKA_MI_LENGTH);
        idx += MKA_MI_LENGTH;
        context[idx   ] = (uint8_t)((kn >> 24U) & 0xFFU);
        context[idx+1U] = (uint8_t)((kn >> 16U) & 0xFFU);
        context[idx+2U] = (uint8_t)((kn >>  8U) & 0xFFU);
        context[idx+3U] = (uint8_t)((kn       ) & 0xFFU);
        idx += 4U;

        sak->length = (uint8_t)out_len;
        result = ieee8021x_aes_kdf(
                /* kdk      */  cak->key,
                /* kdk_len  */  cak->length,
                /* label    */  sak_derivation_label,
                /* label_len*/  sizeof(sak_derivation_label),
                /* context  */  context,
                /* ctx len  */  idx,
                /* ret_bits */  out_len,
                /* ret      */  sak->key
            );
    }

    return result;
}

/**
 * ieee802.1X ICV computation
 * @remark: Assuming peer to peer implementation, only two MI are going to be used.
 * @param[in] aa        Algorithm Agility
 * @param[in] ick       ICK key for computation
 * @param[in] message   Message input for ICV computation
 * @param[in] msg_len   Length of the message
 * @param[out] icv      Output ICV
 * Returns: true on success, false on failure
 */
bool MKA_ComputeICV(uint32_t aa, t_MKA_key const* ick,
                uint8_t const*message, uint32_t msg_len, uint8_t *icv)
{
    bool result;

    // Sanity check - null pointers
    if ((NULL == ick) || (NULL == message) || (NULL == icv)) {
        result = false;

    } // Ok, do compute for 128 bit
    else if ((MKA_ALGORITHM_AGILITY == aa) && (MKA_KEY_128BIT == ick->length)) {
        result = (0 == omac1_aes_128(
                /* key      */  ick->key,
                /* data     */  message,
                /* data_len */  msg_len,
                /* mac      */  icv
        ));

    } // Ok, do compute for 256 bit
    else if ((MKA_ALGORITHM_AGILITY == aa) && (MKA_KEY_256BIT == ick->length)) {
        result = (0 == omac1_aes_256(
                /* key      */  ick->key,
                /* data     */  message,
                /* data_len */  msg_len,
                /* mac      */  icv
        ));
    } // Unsupported aa / key length combination
    else {
        result = false;
    }

    return result;
}

/**
 * ieee802.1X Key wrapping
 * @param[in] kek           KEK wrapping key
 * @param[in] input_key     Input key
 * @param[out] out_wrapped  Output wrapped key, same size than input key
 * Returns: true on success, false on failure
 */
bool MKA_WrapKey(t_MKA_key const*kek, t_MKA_key const*input_key,
                uint8_t*output_wrapped)
{
    bool result;

    // TODO: Crypto module abstraction

    // Sanity check - null pointers
    if ((NULL == kek) || (NULL == input_key) || (NULL == output_wrapped)) {
        result = false;

    } // 128-bit key, (TODO: kek is in RAM)
    else if (MKA_KEY_128BIT == input_key->length) {
        result = (0 == aes_wrap(
            /* kek      */  kek->key,
            /* kek_len  */  kek->length,
            /* n        */  (uint32_t)MKA_KEY_128BIT >> 3U,
            /* plain    */  input_key->key, // 16 bytes to read
            /* cipher   */  output_wrapped  // 24 bytes to write
        ));

    } // 256-bit key, (TODO: kek is in RAM)
    else if (MKA_KEY_256BIT == input_key->length) {
        result = (0 == aes_wrap(
            /* kek      */  kek->key,
            /* kek_len  */  kek->length,
            /* n        */  (uint32_t)MKA_KEY_256BIT >> 3U,
            /* plain    */  input_key->key, // 32 bytes to read
            /* cipher   */  output_wrapped  // 40 bytes to write
        ));
    }
    else {
        result = false;
    }

    return result;
}

/**
 * ieee802.1X Key unwrapping
 * @param[in] kek           KEK wrapping key
 * @param[in] in_wrapped    Incoming wrapped key
 * @param[in] len           Size of wrapped key in bytes
 * @param[out] output_key   Output key
 * Returns: true on success, false on failure
 */
bool MKA_UnwrapKey(t_MKA_key const*kek, uint8_t const*in_wrapped,
                uint32_t len, t_MKA_key *output_key)
{
    bool result;

    // TODO: Crypto module abstraction

    // Sanity check - null pointers
    if ((NULL == kek) || (NULL == in_wrapped) || (NULL == output_key)) {
        result = false;

    } // 128-bit key, (TODO: kek is in RAM)
    else if (MKA_KEY_128BIT_WRAPPED == len) {
        output_key->length = MKA_KEY_128BIT;
        result = (0 == aes_unwrap(
            /* kek      */  kek->key,
            /* kek_len  */  kek->length,
            /* n        */  (uint32_t)MKA_KEY_128BIT >> 3U,
            /* cipher   */  in_wrapped, // 24 bytes to read
            /* plain    */  output_key->key    // 16 bytes to write
        ));

    } // 256-bit key, (TODO: kek is in RAM)
    else if (MKA_KEY_256BIT_WRAPPED == len) {
        output_key->length = MKA_KEY_256BIT;
        result = (0 == aes_unwrap(
            /* kek      */  kek->key,
            /* kek_len  */  kek->length,
            /* n        */  (uint32_t)MKA_KEY_256BIT >> 3U,
            /* cipher   */  in_wrapped, // 40 bytes to read
            /* plain    */  output_key->key    // 32 bytes to write
        ));
    }
    else {
        result = false;
    }

    return result;
}
