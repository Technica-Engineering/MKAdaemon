/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_kay_internal.h
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
*******************************************************************************/
/*******************************************************************************
 * @file        mka_kay_internal.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA KaY internal API's
 *
 * @{
 */

#ifndef MKA_KAY_INTERNAL_H_
#define MKA_KAY_INTERNAL_H_

/*******************        Includes        *************************/
#include "mka_private.h"

/*lint -save */
//lint -e9026 [MISRA 2012 Directive 4.9, advisory] Function-like macros defined for readability

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/
/// IEEE 802.1x-2020 see 9.8 SAK generation, distribution and selection
#define MKA_PN_EXHAUSTION           0xC0000000UL
#define MKA_XPN_EXHAUSTION          0xC000000000000000ULL

/// IEEE 802.1x-2020 11.1.1 parameter encoding
#define PARAMETER_LIVE_PEER_LIST            1U
#define PARAMETER_POTENTIAL_PEER_LIST       2U
#define PARAMETER_SAK_USE                   3U
#define PARAMETER_DISTRIBUTED_SAK           4U
#define PARAMETER_DISTRIBUTED_CAK           5U
#define PARAMETER_KMD                       6U
#define PARAMETER_ANNOUNCEMENT              7U
#define PARAMETER_XPN                       8U
#define PARAMETER_ICV                       255U
#define PARAMETER_NONE                      0xFFFFU

/// IEEE 802.1x-2020 11-8 EAPOL-Announcement TLV
#define TLV_MACSEC_CIPHER_SUITES            112U

// Distribute SAK allowed lengths
#define MKA_DIST_SAK_LEN_EMPTY              0U
#define MKA_DIST_SAK_LEN_DEFAULT            28U
#define MKA_DIST_SAK_LEN_SPECIFIC           36U

// Helpers
#define ETHHDR_FROM_PACKET(packet)  \
    ((t_MKA_l2_ether_header *)(packet))

#define ETHHDR_FROM_CONST_PACKET(packet)  \
    ((t_MKA_l2_ether_header const *)(packet))

#define EAPOL_FROM_PACKET(packet)  \
    ((t_mka_eapol_header *)&(packet)[sizeof(t_MKA_l2_ether_header)])

#define EAPOL_FROM_CONST_PACKET(packet)  \
    ((t_mka_eapol_header const*)&(packet)[sizeof(t_MKA_l2_ether_header)])

#define MKABPM_FROM_PACKET(packet) \
    ((t_mka_basic_parameter_set *)&(packet)[sizeof(t_MKA_l2_ether_header)+sizeof(t_mka_eapol_header)])

#define MKABPM_FROM_CONST_PACKET(packet) \
    ((t_mka_basic_parameter_set const*)&(packet)[sizeof(t_MKA_l2_ether_header)+sizeof(t_mka_eapol_header)])

// Last SAK is either the one being distributed, or the current in use
#define GET_LAST_SAK(participant) \
    ((NULL == (participant)->new_sak.secy_reference) ? \
        &(participant)->current_sak : &(participant)->new_sak)

//lint -estring(9026, BOOL_CAST) [MISRA 2012 Directive 4.9, advisory] function-like macro defined to improve readability
#define BOOL_CAST(x)    \
    /*lint -e{9034} false positive, essential types are equal */\
    ((bool)(x))

#define SSCI_FIRST      1U
#define SSCI_SECOND     2U

#define UNUSED_SA_PN    1U

/*******************        Types             ***********************/
typedef enum {
    MKA_PEER_NONE = 0,
    MKA_PEER_POTENTIAL,
    MKA_PEER_LIVE
} t_mka_peer_state;

typedef enum {
    MKA_SAK_NOT_INSTALLED,
    MKA_SAK_KS_DO_GENERATE_FIRST,
    MKA_SAK_INSTALLED,
    MKA_SAK_KS_DO_GENERATE,
    MKA_SAK_KS_DISTRIBUTING,
    MKA_SAK_KC_INSTALLING
} t_mka_sak_state;

typedef enum {
    MKA_LINK_DOWN,          // C.P. link is down
    MKA_LINK_UP_REPORTING,  // SAK usage is being reported to the peer
    MKA_LINK_UP_EVENT,      // C.P. linkup event can be reported to the system
    MKA_LINK_UP             // C.P. link is up and reported, no further action
} t_mka_link_report;

typedef struct {
    uint8_t             mi[MKA_MI_LENGTH];
    uint32_t            mn;
    t_MKA_sci           sci;
    t_MKA_ssci          ssci;

    bool                key_server;
    uint8_t             key_server_priority;
    bool                macsec_desired;
    t_MKA_macsec_cap    macsec_capability;

    t_MKA_ciphsuite     compatible_cipher;
    t_MKA_macsec_cap    compatible_capability;

    bool                transmits_sak_use;

    t_mka_peer_state    state;
    t_mka_peer_state    remote_state;
    t_mka_timer         expiry;
} t_mka_peer;

typedef struct {
    t_MKA_ki            ki;
    t_MKA_pn            next_pn;
} t_sak_nonce_pair;

typedef struct {
    uint8_t             mi[MKA_MI_LENGTH];
    uint32_t            mn;
} MKA_PACK_STRUCT t_mka_peer_id;

// IEEE 802.1X 9.16, active OR potential participant (myself)
typedef struct {
    t_MKA_ckn           ckn;
    t_MKA_key           cak;
    t_MKA_key           kek;
    t_MKA_key           ick;

    bool                enable;
    bool                retain;
    bool                active;
    bool                is_key_server;

    uint8_t             mi[MKA_MI_LENGTH];
    uint32_t            mn;
    uint32_t            kn; // Latest generated key number

    bool                generate_new_sak;
    bool                distribute_sak;

    bool                advertise_macsec_desired;
    t_MKA_macsec_cap    advertise_macsec_capability;

    t_mka_sak_state     sak_state;
    uint8_t             new_sak_wrapped[MKA_KEY_WRAPPED_MAX];
    t_MKA_sak           new_sak;
    t_MKA_sak           current_sak;
    t_sak_nonce_pair    ks_history[MKA_KS_HISTORY_SIZE];

    // parameters subject to negotiation
    t_MKA_confidentiality_offset    conf_offset;
    t_MKA_ciphsuite     cipher;

    // Peer
    t_mka_peer          peer;

    // backport: potential peer for quick renegotiation after remote MI reset, without full multipeer
    t_mka_peer          peer_secondary;

    // Life time
    t_mka_timer         cak_life;
    t_mka_timer         mka_life;
    t_mka_timer         hello;
    uint8_t             hello_rampup_idx;

    bool                invalid_icv_received; // For reporting only
} t_mka_participant;

typedef struct {
    int_atomic_t        enable_request;
    int_atomic_t        enable;

    bool                active;
    t_MKA_connect_mode  mode; // translates to {authenticated, secured, failed}
    //bool                authenticated;
    //bool                secured;
    //bool                failed;

    t_MKA_sci           actor_sci;
    uint8_t             actor_priority;
    t_MKA_sci           key_server_sci;
    uint8_t             key_server_priority;

    // Transmission Secure Channel (one per bus)
    t_MKA_transmit_sc   *txsc;

    // Reception Secure Channel (one per participant)
    t_MKA_receive_sc    *rxsc;

    // Secy configuration issue occurred
    bool                secy_error_occurred;

    t_MKA_macsec_cap    macsec_capable;
    //bool                macsec_desired; // Redundant
    //bool                macsec_protect; // Redundant
    bool                macsec_delay_protect;
    //t_MKA_validate_frames macsec_validate; // Redundant
    bool                macsec_replay_protect;
    uint32_t            macsec_replay_window;

    bool                new_info; // Transmit mark
    t_MKA_role          role;
    t_mka_link_report   linkup_report;
    t_MKA_bus_info      state_info;

    // This implementation is limited to one single participant instantiation
    t_mka_participant   participant;
} t_mka_kay;

typedef struct {
    uint8_t         version;
    uint8_t         type;
    uint16_t        body_length;
} MKA_PACK_STRUCT t_mka_eapol_header;

typedef struct {
    uint8_t         header;
    uint8_t         specific1;
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          length : 4;
    uint_t          specific2 : 4;
#else // BIG ENDIAN
    uint_t          specific2 : 4;
    uint_t          length : 4;
#endif
    uint8_t         length_cont;
} MKA_PACK_STRUCT t_mka_param_generic;

typedef struct {
    uint8_t         version;
    uint8_t         priority;
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          length : 4;
    uint_t          macsec_capability : 2;
    bool            macsec_desired : 1;
    bool            key_server : 1;
#else // BIG ENDIAN
    bool            key_server : 1;
    bool            macsec_desired : 1;
    uint_t          macsec_capability : 2;
    uint_t          length : 4;
#endif

    uint8_t         length_cont;
    t_MKA_sci       sci;
    uint8_t         actor_mi[MKA_MI_LENGTH];
    uint32_t        actor_mn;
    
    uint32_t        algorithm_agility;

    // CKN follows
} MKA_PACK_STRUCT t_mka_basic_parameter_set;

typedef struct {
    uint8_t         type;
    uint8_t         key_server_ssci;
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          length : 4;
    uint_t          unused : 4;
#else // BIG ENDIAN
    uint_t          unused : 4;
    uint_t          length : 4;
#endif
    uint8_t         length_cont;
} MKA_PACK_STRUCT t_mka_param_peer_list;

typedef struct {
    uint8_t         type;
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    bool            orx : 1;
    bool            otx : 1;
    uint_t          oan : 2;
    bool            lrx : 1;
    bool            ltx : 1;
    uint_t          lan : 2;
#else // BIG ENDIAN
    uint_t          lan : 2;
    bool            ltx : 1;
    bool            lrx : 1;
    uint_t          oan : 2;
    bool            otx : 1;
    bool            orx : 1;
#endif
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          length : 4;
    bool            delay_protect : 1;
    bool            unused : 1;
    bool            plain_rx : 1;
    bool            plain_tx : 1;
#else // BIG ENDIAN
    bool            plain_tx : 1;
    bool            plain_rx : 1;
    bool            unused : 1;
    bool            delay_protect : 1;
    uint_t          length : 4;
#endif
    uint8_t         length_cont;

    uint8_t         latest_kmi[MKA_MI_LENGTH];
    uint32_t        latest_kn;
    uint32_t        latest_laccpn; // latest lowest acceptable PN

    uint8_t         old_kmi[MKA_MI_LENGTH];
    uint32_t        old_kn;
    uint32_t        old_laccpn; // oldest lowest acceptable PN
    
} MKA_PACK_STRUCT t_mka_sak_use;

typedef struct {
    uint8_t         type;
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          unused : 4;
    uint_t          confidentiality_offset : 2;
    uint_t          distributed_an : 2;
#else // BIG ENDIAN
    uint_t          distributed_an : 2;
    uint_t          confidentiality_offset : 2;
    uint_t          unused : 4;
#endif
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          length : 4;
    uint_t          unused2 : 4;
#else // BIG ENDIAN
    uint_t          unused2 : 4;
    uint_t          length : 4;
#endif
    uint8_t         length_cont;

    uint32_t        key_number;
    
    // key wrap follows
} MKA_PACK_STRUCT t_mka_dist_sak;

typedef struct {
    uint8_t         type;
    uint8_t         suspension_time;
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          length : 4;
    uint_t          unused : 4;
#else // BIG ENDIAN
    uint_t          unused : 4;
    uint_t          length : 4;
#endif
    uint8_t         length_cont;

    uint32_t        latest_laccpn_high;
    uint32_t        old_laccpn_high;
    
} MKA_PACK_STRUCT t_mka_xpn;

typedef struct {
    uint8_t         reserved;
#if MKA_ENDIANNESS == MKA_LITTLE_ENDIAN
    uint_t          cs_impl_capability : 2;
    uint_t          reserved2 : 6;
#else // BIG ENDIAN
    uint_t          reserved2 : 6;
    uint_t          cs_impl_capability : 2;
#endif
    t_MKA_ciphsuite ciphersuite;
    
} MKA_PACK_STRUCT t_mka_tlv_macsec_cipher_suites;

/*******************        Variables         ***********************/
extern t_mka_kay mka_kay[MKA_NUM_BUSES];

/*******************        Func. prototypes  ***********************/
void mka_receive_from_l2(t_MKA_bus bus);
uint8_t const* mka_packet_find_icv(uint8_t const*packet, uint32_t *length);

bool mka_mkpdu_verify(t_MKA_bus bus, uint8_t const*packet, uint32_t *length);
void mka_handle_mkpdu(t_MKA_bus bus, uint8_t const*packet, uint32_t length);
bool mka_handle_basic_parameter_set(t_MKA_bus bus, t_mka_basic_parameter_set const*bps);
bool mka_encode_basic_parameter_set(t_MKA_bus bus, uint8_t *packet, uint32_t *length);
bool mka_handle_peer_list(t_MKA_bus bus, uint8_t const*param, uint32_t body_len, bool main_peer, t_mka_peer_state type);
bool mka_encode_peer_list(t_MKA_bus bus, uint8_t *packet, uint32_t *length);
bool mka_handle_sak_use(t_MKA_bus bus, uint8_t const*param, uint32_t body_len);
bool mka_encode_sak_use(t_MKA_bus bus, uint8_t *packet, uint32_t *length);
bool mka_handle_distributed_sak(t_MKA_bus bus, uint8_t const*param, uint32_t body_len);
bool mka_encode_distributed_sak(t_MKA_bus bus, uint8_t *packet, uint32_t *length);
bool mka_encode_xpn(t_MKA_bus bus, uint8_t *packet, uint32_t *length);
bool mka_handle_announcement_macsec_ciphersuites(t_MKA_bus bus, uint8_t const*tlv, uint32_t length);
bool mka_handle_announcements(t_MKA_bus bus, uint8_t const*param, uint32_t body_len);
bool mka_encode_announcements(t_MKA_bus bus, uint8_t *packet, uint32_t *length);
bool mka_encode_icv(t_MKA_bus bus, uint8_t *packet, uint32_t *length);

bool mka_update_txsa_pn(t_MKA_bus bus);
void mka_peer_cleanup(t_MKA_bus bus);
void mka_participant_cleanup(t_MKA_bus bus);
void mka_new_participant_mi(t_MKA_bus bus);
uint16_t mka_mkpdu_get_parameter(uint8_t const*packet, uint32_t offset, uint32_t length, uint32_t *param_len);
bool mka_elect_key_server(t_MKA_bus bus);
bool mka_create_new_sak(t_MKA_bus bus);
bool mka_select_macsec_usage(t_MKA_bus bus);
void mka_set_mode(t_MKA_bus bus, t_MKA_connect_mode mode);
t_MKA_sak* mka_find_key(t_MKA_bus bus, uint8_t const* mi, uint32_t kn);
void mka_transmit_mkpdu(t_MKA_bus bus);
bool mka_sak_nonce_protection(t_MKA_bus bus, uint8_t const* mi, uint32_t kn, t_MKA_pn next_pn);

/*******************        Func. definition  ***********************/
static inline t_MKA_macsec_cap mka_macsec_cap_min(t_MKA_macsec_cap a, t_MKA_macsec_cap b)
{
    uint8_t const a_numeric = (uint8_t)a;
    uint8_t const b_numeric = (uint8_t)b;

    return (a_numeric < b_numeric) ? a : b;
}

static inline bool mka_alg_agility_supported(uint32_t x)
{
    return MKA_ALGORITHM_AGILITY == x;
}

static inline uint32_t mka_get_param_size(uint8_t const* param_bytes)
{
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_param_generic const* param = (t_mka_param_generic const*)param_bytes;
    return ((uint32_t)param->length << 8U) | (uint32_t)param->length_cont;
}

static inline uint8_t mka_get_param_type(uint8_t const* param_bytes)
{
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_param_generic const* param = (t_mka_param_generic const*)param_bytes;
    return param->header;
}

static inline bool mka_frame_account_space(uint32_t *length, uint32_t how_much)
{
    bool const fits = (*length - MKA_EAPOL_MAX_SIZE) >= how_much;
    (*length) += fits ? how_much : 0U;
    return fits;
}

static inline bool mka_macsec_supported(t_mka_kay const*ctx)
{
    return (MKA_MACSEC_NOT_IMPLEMENTED != ctx->macsec_capable);
}

static inline bool mka_macsec_enabled(t_mka_kay const*ctx)
{
    return mka_macsec_supported(ctx) && (MKA_CS_NULL != ctx->participant.cipher) &&
        (MKA_MACSEC_NOT_IMPLEMENTED != ctx->participant.advertise_macsec_capability);
}

static inline bool mka_is_cipher_acceptable(t_MKA_bus bus, t_MKA_ciphsuite cipher)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    bool acceptable = false;
    uint8_t i;

    for(i=0U; (i<MKA_ARRAY_SIZE(cfg->impl.cipher_preference)) && (!acceptable); ++i) {
        acceptable = (cfg->impl.cipher_preference[i] == cipher);
    }

    return acceptable;
}

static inline t_MKA_sak* mka_get_latest(t_MKA_bus bus, uint8_t* lan, bool* ltx, bool* lrx)
{
    t_MKA_ki const* ki = NULL;
    MKA_CP_GetLatestSA(bus, &ki, lan, ltx, lrx);
    return (NULL == ki) ? NULL : mka_find_key(bus, ki->mi, ki->kn);
}

static inline t_MKA_sak* mka_get_old(t_MKA_bus bus, uint8_t* oan, bool* otx, bool* orx)
{
    t_MKA_ki const* ki = NULL;
    MKA_CP_GetOldSA(bus, &ki, oan, otx, orx);
    return (NULL == ki) ? NULL : mka_find_key(bus, ki->mi, ki->kn);
}

static inline bool mka_is_cipher_xpn(t_MKA_ciphsuite cipher)
{
    return (MKA_CS_ID_GCM_AES_XPN_256 == cipher) ||
            (MKA_CS_ID_GCM_AES_XPN_128 == cipher);
}

static inline void mka_update_laccpn_xpn_logic(t_MKA_sak*dst, uint32_t laccpn)
{
    uint64_t new_pn = dst->next_pn & 0xFFFFFFFF00000000UL; // 32 msb (XPN ciphersuites)
    new_pn = new_pn | (uint64_t)laccpn; // add 32 lsb from peer

    // XPN wrap-around (assuming time to wrap-around << MKA period, which is a safe assumption up to 1Tb/s)
    if (new_pn < dst->next_pn) {
        new_pn += 0x100000000UL; // Increase by 2^32
    }

    dst->next_pn = new_pn; // update
}

#ifdef __cplusplus
}
#endif

/*lint -restore */

#endif /* MKA_KAY_INTERNAL_H_ */

/** @} */
