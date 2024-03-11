/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_kay_params.c
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
 * @file        mka_kay_params.c
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA KaY implementation
 *
 * @{
 */

/*******************        Includes        *************************/
#include "mka_kay_internal.h"

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/

uint16_t mka_mkpdu_get_parameter(uint8_t const*packet, uint32_t offset, uint32_t length, uint32_t *param_len)
{
    uint32_t available = length - offset;
    uint16_t result_type = PARAMETER_NONE;

    if (sizeof(t_mka_param_generic) <= available) {
        *param_len = mka_get_param_size(&packet[offset]);

        if ((sizeof(t_mka_param_generic) + *param_len) <= available) {
            result_type = mka_get_param_type(&packet[offset]);
        }
        else {
            *param_len = 0U;
        }
    }

    return result_type;
}

bool mka_mkpdu_verify(t_MKA_bus bus, uint8_t const*packet, uint32_t *length)
{
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_MKA_l2_ether_header const*const ethhdr = ETHHDR_FROM_CONST_PACKET(packet);
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_eapol_header const*const eapolhdr = EAPOL_FROM_CONST_PACKET(packet);
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_basic_parameter_set const*const bps = MKABPM_FROM_CONST_PACKET(packet);
    uint16_t mkpdu_length = MKA_NTOHS(eapolhdr->body_length);
    uint8_t const*mkpdu = &packet[sizeof(t_MKA_l2_ether_header)+sizeof(t_mka_eapol_header)];

    t_mka_kay *const ctx = &mka_kay[bus];
    t_mka_participant *const participant = &ctx->participant;
    uint8_t icv[MKA_ICV_LENGTH];
    uint8_t const*incoming_icv = NULL;
    t_MKA_ckn ckn = {{0U}, 0U};
    uint32_t bps_len = 0U;
    bool is_valid;

    // IEEE 802.1X 11.11.2 verification (a)
    if (MKA_l2_is_individual_addr(ethhdr->dst)) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU addressed to individual address. Discarding.", bus);
        is_valid = false;
    } // IEEE 802.1X 11.11.2 verification (b)
    else if (mkpdu_length < MKA_MKPDU_MIN_LENGTH) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU less than 32 octets long. Discarding.", bus);
        is_valid = false;
    } // IEEE 802.1X 11.11.2 verification (c)
    else if ((mkpdu_length & 3U) > 0U) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with a length %i non-multiple of 4. Discarding.", bus, mkpdu_length);
        is_valid = false;
    } // Continue
    else {
        bps_len = ((uint32_t)bps->length << 8U) | (uint32_t)bps->length_cont;
        is_valid = true;
    }

    // Case frame has already been discarded (prevent if-nesting, better readability)
    if (!is_valid) {
        // No further action

    } // IEEE 802.1X 11.11.2 verification (d) Minimum length case when CKN's length is exactly 1 byte
    else if (bps_len < (MKA_CKN_MIN + sizeof(t_mka_basic_parameter_set) - sizeof(t_mka_param_generic))) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with no CKN. Discarding.", bus, mkpdu_length);
        is_valid = false;

    } // IEEE 802.1X 11.11.2 verification (d) Maximum length case when CKN's length is maximum
    else if (bps_len > (MKA_CKN_MAX + sizeof(t_mka_basic_parameter_set) - sizeof(t_mka_param_generic))) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with CKN too large. Discarding.", bus, mkpdu_length);
        is_valid = false;

    } // IEEE 802.1X 11.11.2 verification (d) Case where BPM's length cannot fit inside MKPDU message along with an ICV
    else if (mkpdu_length < (bps_len + sizeof(t_mka_param_generic) + MKA_ICV_LENGTH)) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with length smaller than BasicParameterSet + ICV. Discarding.", bus, mkpdu_length);
        is_valid = false;

    }
    else {
        if (MKA_MKPDU_VERSION_ID != bps->version) {
#if defined(MKA_ALLOW_OTHER_VERSIONS) && (0 != MKA_ALLOW_OTHER_VERSIONS) //lint !e9029 evaluates fine in preprocessor
            MKA_LOG_DEBUG3("KaY/%i: Received MKPDU with different version %i. Silently ignoring.", bus, bps->version);
#else
            MKA_LOG_WARNING("KaY/%i: Received MKPDU with unsupported version %i. Discarding.", bus, bps->version);
            is_valid = false;
#endif
        }
        ckn.length = (uint8_t)((bps_len - sizeof(t_mka_basic_parameter_set)) + sizeof(t_mka_param_generic));
        memcpy(ckn.name, &mkpdu[sizeof(t_mka_basic_parameter_set)], ckn.length);
    }

    // Case frame has already been discarded (prevent if-nesting, better readability)
    if (!is_valid) {
        // No further action

    } // IEEE 802.1X 11.11.2 verification (f) comparing CKN with my own
    else
    //lint -e{644} false positive, the only path for ckn to be uninitialised is when is_valid == false
    if (participant->ckn.length != ckn.length) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with different CKN length. Discarding.", bus);
        is_valid = false;
    } // IEEE 802.1X 11.11.2 verification (f) comparing CKN with my own
    else if (0 != memcmp(participant->ckn.name, ckn.name, ckn.length)) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with different CKN. Discarding.", bus);
        is_valid = false;

    } // IEEE 802.1X 11.11.2 verification (g) regarding Algorithm Agility
    else if (!mka_alg_agility_supported(MKA_HTONL(bps->algorithm_agility))) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with unexpected Algorithm Agility. Discarding.", bus);
        is_valid = false;
    }
    else {
        // IEEE 802.1X 11.11.2 verification (f) ICV cryptographic check
        incoming_icv = mka_packet_find_icv(packet, length);
        if (NULL == incoming_icv) {
            MKA_LOG_ERROR("KaY/%i: Cannot find ICV in incoming packet! Discarding.", bus);
            is_valid = false;
        }
        else if (!MKA_ComputeICV(
                /* alg. agility */  MKA_HTONL(bps->algorithm_agility),
                /* ick          */  &participant->ick,
                /* message      */  packet,
                /* msg_len      */  *length - MKA_ICV_LENGTH,
                /* ICV          */  icv
                        )){
            MKA_LOG_WARNING("KaY/%i: Cannot compute ICV, error from crypto module! Discarding frame.", bus);
            is_valid = false;
        }
        else {
            // no further action,
        }
    }

    // Case frame has already been discarded
    if (!is_valid) {
        // No further action

    } // IEEE 802.1X 11.11.2 verification (f) ICV
    else
    //lint -e{645, 644, 668} false positive, the only path for icv/incoming_icv to be uninitialised is when is_valid == false
    if (0 != memcmp(icv, incoming_icv, MKA_ICV_LENGTH)) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with invalid ICV. Discarding.", bus);
        participant->invalid_icv_received = true;
        is_valid = false;
    }
    else {
        // No further action, frame accepted
        participant->invalid_icv_received = false;
    }

    return is_valid;
}


bool mka_handle_basic_parameter_set(t_MKA_bus bus, t_mka_basic_parameter_set const*bps)
{
    bool continue_process = true;
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer *const peer = &participant->peer;
    t_mka_peer *const peer_secondary = &participant->peer_secondary;

    // Comparisons for evaluating colliding MI
    bool const is_sci_addr_same_mine = (0 == memcmp(bps->sci.addr, ctx->actor_sci.addr, MKA_L2_ADDR_SIZE));
    bool const is_mi_same_mine = MKA_mi_equal(participant->mi, bps->actor_mi);
    bool const peer_mi_match = MKA_mi_equal(peer->mi, bps->actor_mi);

    // Role verification, enforced when there's a relation with peer
    if ((MKA_ROLE_FORCE_KEY_SERVER == ctx->role) && (1U == bps->key_server) && (MKA_PEER_NONE != peer->state) && peer_mi_match) {
        MKA_LOG_WARNING("KaY/%i: Configured as Key Server, received packet from a Key Server. Discarded.", bus);
        continue_process = false;
    }

    // Role verification, enforced when there's a relation with peer
    if ((MKA_ROLE_FORCE_KEY_CLIENT == ctx->role) && (0U == bps->key_server) && (MKA_PEER_NONE != peer->state) && peer_mi_match) {
        MKA_LOG_WARNING("KaY/%i: Configured as non Key Server, received packet from a non Key Server. Discarded.", bus);
        continue_process = false;
    }

    // Version already validated
    // Algorithm Agility already validated
    // CKN already validated

    if (is_sci_addr_same_mine) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with our own SCI address (replay attack?). Dropped.", bus);
        continue_process = false;
    }
    else if (is_mi_same_mine) {
        MKA_LOG_INFO("KaY/%i: Received packet with MI that collides with bus actor's, selecting new MI.", bus);
        mka_new_participant_mi(bus);
        continue_process = false;

    } // Case no peer registered yet
    else if (MKA_PEER_NONE == peer->state) {
        MKA_LOG_INFO("KaY/%i: New potential peer.", bus);
        // Register. It is now a potential peer
        memcpy(peer->sci.addr, bps->sci.addr, MKA_L2_ADDR_SIZE);
        peer->sci.port = MKA_NTOHS(bps->sci.port);
        memcpy(peer->mi, bps->actor_mi, MKA_MI_LENGTH);
        peer->mn = MKA_NTOHL(bps->actor_mn);
        peer->key_server = (bps->key_server > 0U);
        peer->key_server_priority = bps->priority;
        peer->macsec_desired = (bps->macsec_desired > 0U);
        //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        peer->macsec_capability = (t_MKA_macsec_cap)bps->macsec_capability;
        //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        peer->compatible_capability = (t_MKA_macsec_cap)bps->macsec_capability;
        peer->state = MKA_PEER_POTENTIAL;

#if MKA_TRANSMIT_ON_PEER_LEARNT
        ctx->new_info = true; // Speed up handshake
#endif
        mka_timer_start(&peer->expiry, MKA_active_global_config->life_time);

    } // Case SCI differs
    else if ((0 != memcmp(peer->sci.addr, bps->sci.addr, MKA_L2_ADDR_SIZE)) ||
                (peer->sci.port != MKA_HTONS(bps->sci.port))) {
        MKA_LOG_INFO("KaY/%i: Received MKPDU from peer from different SCI, but peer slot is occupied. Discarded.", bus);
        continue_process = false;

    } // Case MI differs
    else if (!peer_mi_match) {
        if (MKA_PEER_NONE == peer_secondary->state) {
            MKA_LOG_INFO("KaY/%i: Received MKPDU from peer with same SCI, different MI. Learning as secondary until live.", bus);

            // Register. It is now a potential peer
            memcpy(peer_secondary->sci.addr, bps->sci.addr, MKA_L2_ADDR_SIZE);
            peer_secondary->sci.port = MKA_NTOHS(bps->sci.port);
            memcpy(peer_secondary->mi, bps->actor_mi, MKA_MI_LENGTH);
            peer_secondary->mn = MKA_NTOHL(bps->actor_mn);
            peer_secondary->key_server = (bps->key_server > 0U);
            peer_secondary->key_server_priority = bps->priority;
            peer_secondary->macsec_desired = (bps->macsec_desired > 0U);
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            peer_secondary->macsec_capability = (t_MKA_macsec_cap)bps->macsec_capability;
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            peer_secondary->compatible_capability = (t_MKA_macsec_cap)bps->macsec_capability;
            peer_secondary->state = MKA_PEER_POTENTIAL;

            ctx->new_info = true; // Speed up handshake
            mka_timer_start(&peer_secondary->expiry, MKA_active_global_config->life_time);

        } // Repeated Message Number
        else if (peer_secondary->mn >= MKA_NTOHL(bps->actor_mn)) {
            MKA_LOG_WARNING("KaY/%i: Received MKPDU from secondary peer with lower MN than expected. Discarded.", bus);
            continue_process = false;
        }
        else if (MKA_mi_equal(peer_secondary->mi, bps->actor_mi)) {
            peer_secondary->mn = MKA_NTOHL(bps->actor_mn);
            peer_secondary->key_server = (bps->key_server > 0U);
            peer_secondary->key_server_priority = bps->priority;
            peer_secondary->macsec_desired = (bps->macsec_desired > 0U);
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            peer_secondary->macsec_capability = (t_MKA_macsec_cap)bps->macsec_capability;
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            peer_secondary->compatible_capability = (t_MKA_macsec_cap)bps->macsec_capability;

            mka_timer_start(&peer_secondary->expiry, MKA_active_global_config->life_time);
        }
        else {
            MKA_LOG_INFO("KaY/%i: Received MKPDU with same SCI, different MI, but secondary slot occupied. Discarded.", bus);
            continue_process = false;
        }

    } // Repeated Message Number
    else if (peer->mn >= MKA_NTOHL(bps->actor_mn)) {
        MKA_LOG_WARNING("KaY/%i: Received MKPDU with lower MN than expected. Discarded.", bus);
        continue_process = false;

    } // Message Number in sequence
    else {
        peer->mn = MKA_NTOHL(bps->actor_mn);
        peer->key_server = (bps->key_server > 0U);
        peer->key_server_priority = bps->priority;
        peer->macsec_desired = (bps->macsec_desired > 0U);
        //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        peer->macsec_capability = (t_MKA_macsec_cap)bps->macsec_capability;
        //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        peer->compatible_capability = (t_MKA_macsec_cap)bps->macsec_capability;
        // timer to be updated once all parameters successfully decoded
    }

    return continue_process;
}

bool mka_encode_basic_parameter_set(t_MKA_bus bus, uint8_t *packet, uint32_t *length)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_basic_parameter_set *const bps = (t_mka_basic_parameter_set*)&packet[*length];
    uint8_t *const ckn_space = &packet[(*length) + sizeof(t_mka_basic_parameter_set)];
    bool continue_process = true;

    // No space
    if (!mka_frame_account_space(length, sizeof(t_mka_basic_parameter_set) + participant->ckn.length)) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to Basic Parameter Set encoding error.", bus);
        continue_process = false;
    }
    else {
        memset(bps, 0, sizeof(t_mka_basic_parameter_set));
        bps->version = MKA_MKPDU_VERSION_ID;
        if (MKA_ROLE_FORCE_KEY_SERVER == ctx->role) {
            bps->priority = 0U; // override to maximum priority to still have a chance autonegotiating
        }
        else if (MKA_ROLE_FORCE_KEY_CLIENT == ctx->role) {
            bps->priority = 0xFFU; // override to minimum priority to still have a chance autonegotiating
        }
        else {
            bps->priority = ctx->actor_priority;
        }
        // Live peer, election happened
        if (MKA_PEER_LIVE == peer->state) {
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 4-value enum to 2-bit number is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 4-value enum to 2-bit number is controlled, values match to enum's
            bps->macsec_capability = (uint_t)participant->advertise_macsec_capability;
            bps->macsec_desired = BOOL_CAST(participant->advertise_macsec_desired);
            bps->key_server = BOOL_CAST(participant->is_key_server);
        }
        else {
            bool const macsec_support = mka_macsec_supported(ctx);
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 4-value enum to 2-bit number is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 4-value enum to 2-bit number is controlled, values match to enum's
            bps->macsec_capability = macsec_support ? ((uint_t)ctx->macsec_capable) : ((uint_t)MKA_MACSEC_NOT_IMPLEMENTED);
            bps->macsec_desired = BOOL_CAST(macsec_support);
            bps->key_server = BOOL_CAST((MKA_ROLE_FORCE_KEY_SERVER == ctx->role) ||
                (MKA_ROLE_FORCE_KEY_CLIENT != ctx->role));
        }
        memcpy(bps->sci.addr, ctx->actor_sci.addr, sizeof(bps->sci.addr));
        bps->sci.port = MKA_NTOHS(ctx->actor_sci.port);
        memcpy(bps->actor_mi, participant->mi, sizeof(participant->mi));
        bps->actor_mn = MKA_HTONL(participant->mn);
        bps->algorithm_agility = MKA_HTONL(MKA_ALGORITHM_AGILITY);

        bps->length = 0U;
        bps->length_cont = (uint8_t)participant->ckn.length +
            (uint8_t)((uint8_t)sizeof(t_mka_basic_parameter_set) - (uint8_t)sizeof(t_mka_param_generic));

        memcpy(ckn_space, participant->ckn.name, participant->ckn.length);
    }

    return continue_process;
}

bool mka_handle_peer_list(t_MKA_bus bus, uint8_t const*param, uint32_t body_len, bool main_peer, t_mka_peer_state type)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer*const peer = &participant->peer;
    t_mka_peer*const peer_secondary = &participant->peer_secondary;
    bool continue_process = true;
    bool self_seen = false;

    if (0U != (body_len & 0xFU)) {
        MKA_LOG_ERROR("KaY/%i: Received MKPDU with peer list length not multiple of 16 bytes, discarding.", bus);
        continue_process = false;
    }
    else {
        uint32_t offset;
        // Iterate peers contained in list
        for(offset = 0U; offset < body_len; offset += sizeof(t_mka_peer_id)) {
            //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
            t_mka_peer_id const* peer_id = (t_mka_peer_id const*)&param[sizeof(t_mka_param_generic)+offset];
            uint32_t const peer_mn = MKA_NTOHL(peer_id->mn);

            // Different MI
            if (!MKA_mi_equal(peer_id->mi, participant->mi)) {
                MKA_LOG_DEBUG3("KaY/%i: Received peer list with different MI.", bus);
                // Just continue

            } // case peer has seen our MI, and has seen a MN higher than ours (duplicated MI?)
            else if (peer_mn > participant->mn) {
                MKA_LOG_INFO("KaY/%i: Received peer list with my MI and MN not emitted yet. Selecting new MI and discarding.", bus);
                // abort and select a new MI
                continue_process = false;
                mka_new_participant_mi(bus);

            } // "acceptably recent MN"
            else if ((participant->mn == peer_mn) || \
                        ((participant->mn > 1U) && (participant->mn == (1U + peer_mn)))) {
                self_seen = true;

            } // peer has seen an old MN from us,
            else {
                MKA_LOG_DEBUG3("KaY/%i: Received peer list with my MI but very old MN. Discarded.", bus);
                // we are not seen by peer
            }
        }
    }

    // Case secondary peer became live
    if (continue_process && self_seen && (MKA_PEER_POTENTIAL == peer_secondary->state) && (!main_peer)) {
        t_MKA_ciphsuite const current_cipher = participant->cipher;
        t_MKA_ciphsuite const current_compat_cipher = peer->compatible_cipher;
        t_MKA_macsec_cap const current_compat_cap = peer->compatible_capability;

        MKA_LOG_INFO("KaY/%i: Secondary peer is live. Replacing primary.", bus);
        // kill main peer and any active SA/SC
        mka_peer_cleanup(bus);

        // signal connectivity change to CP via server changed
        MKA_CP_SignalChgdServer(bus);

        // temporary connection mode transition
        mka_set_mode(bus, MKA_PENDING); // not setting FAILED here on purpose, let timer functions handle

        // make sure to "unfreeze" CP from states RECEIVE and TRANSMIT
        MKA_CP_SetUsingReceiveSAs(bus, true);
        MKA_CP_SetUsingTransmitSA(bus, true);

        // transform secondary peer into primary
        (void)memcpy(peer, peer_secondary, sizeof(*peer));
        (void)memset(&peer->expiry, 0, sizeof(peer->expiry));
        mka_timer_start(&peer->expiry, MKA_active_global_config->life_time);

        // secondary cleanup
        memset(peer_secondary, 0, sizeof(*peer_secondary));
        mka_timer_init(&peer_secondary->expiry);
        main_peer = true;

        // apply previous ciphersuite / negotiation result
        participant->cipher = current_cipher;
        peer->compatible_cipher = current_compat_cipher;
        peer->compatible_capability = current_compat_cap;
    }

    if (main_peer && self_seen) {
        peer->remote_state = type;
    }

    // When a potential peer sees us, peer becomes live
    if (continue_process && self_seen && main_peer && (MKA_PEER_POTENTIAL == peer->state)) {
        MKA_LOG_INFO("KaY/%i: New live peer.", bus);
        peer->state = MKA_PEER_LIVE;

        // Agreement on key server?
        if (!mka_elect_key_server(bus)) {
            MKA_LOG_WARNING("KaY/%i: Key server negotiation failed!", bus);
            continue_process = false;

        } // all good
        else {
            // Leave cipher suite as "invalid" for now
            participant->cipher = MKA_CS_INVALID;

            // compute SSCI of remote peer

            // according to 802.1ae (10.7.13 Receive SA creation), SSCI is
            // assigned from 1..N according to the numerical order of SCI
            // in our case, N=2; we just have to compare SCI's with the peer's
            int32_t sci_compare = memcmp(&peer->sci, &ctx->actor_sci, sizeof(t_MKA_sci));

            // peer's SCI has a higher numerical value -> it gets first SSCI
            peer->ssci = (sci_compare > 0) ? (uint32_t)SSCI_FIRST : (uint32_t)SSCI_SECOND;
        }

        mka_timer_start(&participant->hello, ctx->macsec_delay_protect ?
                        MKA_active_global_config->bounded_hello_time : MKA_active_global_config->hello_time);

#if MKA_TRANSMIT_ON_PEER_LEARNT
        ctx->new_info = ctx->new_info || continue_process; // Speed up handshake
#endif
    }

    // If a live peer doesn't see us, we ignore the frame
    if (continue_process && (!self_seen) && main_peer && (MKA_PEER_LIVE == peer->state) &&
                        (PARAMETER_LIVE_PEER_LIST == *param)) {
        MKA_LOG_WARNING("KaY/%i: We are not listed in our peer live list while peer is live. Discarded.", bus);
        continue_process = false;
    }

    return continue_process;
}

bool mka_encode_peer_list(t_MKA_bus bus, uint8_t *packet, uint32_t *length)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    t_mka_peer const*const peer_secondary = &participant->peer_secondary;
    t_mka_peer const*const peer = &participant->peer;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_param_peer_list * param = (t_mka_param_peer_list*)&packet[*length];
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_peer_id * param_peer = (t_mka_peer_id*)&packet[(*length) + sizeof(t_mka_param_peer_list)];
    bool const present = (MKA_PEER_NONE != peer->state);
    bool const dist_sak_present_xpn = mka_is_cipher_xpn(participant->cipher) && (MKA_SAK_KS_DISTRIBUTING == participant->sak_state);
    bool continue_process = true;

    // Case it's not necessary to include this parameter
    if (!present) {
        // No action

    } // No space
    else if (!mka_frame_account_space(length, sizeof(t_mka_param_peer_list) + sizeof(t_mka_peer_id))) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to Peer List encoding error.", bus);
        continue_process = false;
    }
    else {
        memset(param, 0, sizeof(t_mka_param_peer_list));
        param->type = (MKA_PEER_POTENTIAL == peer->state) ?
            PARAMETER_POTENTIAL_PEER_LIST : PARAMETER_LIVE_PEER_LIST;
        param->key_server_ssci = 0U;
        param->unused = 0U;
        param->length = 0U;
        param->length_cont = 16U;

        if ((MKA_PEER_LIVE == peer->state) && dist_sak_present_xpn) {
            param->key_server_ssci = (peer->ssci == SSCI_FIRST) ? (uint8_t)SSCI_SECOND : (uint8_t)SSCI_FIRST;
        }

        memcpy(param_peer->mi, peer->mi, sizeof(peer->mi));
        param_peer->mn = MKA_HTONL(peer->mn);
    }

    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    param = (t_mka_param_peer_list*)&packet[*length];
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    param_peer = (t_mka_peer_id*)&packet[(*length) + sizeof(t_mka_param_peer_list)];

    // Case not necessary to include potential peer list for quick renegotiation
    if (!present || !continue_process || (MKA_PEER_NONE == peer_secondary->state)) {
        // No action
    }
    else if (!mka_frame_account_space(length, sizeof(t_mka_param_peer_list) + sizeof(t_mka_peer_id))) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to Peer List encoding error.", bus);
        continue_process = false;
    }
    else {
        memset(param, 0, sizeof(t_mka_param_peer_list));
        param->type = PARAMETER_POTENTIAL_PEER_LIST;
        param->key_server_ssci = 0U;
        param->unused = 0U;
        param->length = 0U;
        param->length_cont = 16U;
        param->key_server_ssci = 0U;

        memcpy(param_peer->mi, peer_secondary->mi, sizeof(peer_secondary->mi));
        param_peer->mn = MKA_HTONL(peer_secondary->mn);
    }

    return continue_process;
}

bool mka_handle_distributed_sak(t_MKA_bus bus, uint8_t const*param, uint32_t body_len)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_dist_sak const*const content = (t_mka_dist_sak const*)param;
    uint8_t const* body_past_kn = &param[sizeof(t_mka_dist_sak)];
    uint32_t const incoming_kn = MKA_NTOHL(content->key_number);
    bool continue_process = true;
    bool error = false;
    uint32_t sak_wrapped_len = 0U;
    uint8_t const* sak_wrapped = NULL;
    t_MKA_sak const*const current_sak = GET_LAST_SAK(participant);
    t_MKA_sak* sak = NULL;
    t_MKA_key sak_holder;

    if ((MKA_DIST_SAK_LEN_EMPTY != body_len) && (MKA_DIST_SAK_LEN_DEFAULT != body_len) && \
                                                    (MKA_DIST_SAK_LEN_SPECIFIC > body_len)) {
        MKA_LOG_ERROR("KaY/%i: Received DISTRIBUTED SAK with invalid length. Discarded.", bus);
        error = true;
    }
    else if (MKA_PEER_LIVE != peer->state) {
        MKA_LOG_WARNING("KaY/%i: Received DISTRIBUTED SAK from non-live peer. Discarded.", bus);
        error = true;
    }
    else if (participant->is_key_server) {
        MKA_LOG_ERROR("KaY/%i: Received DISTRIBUTED SAK but I am Key Server. Discarded.", bus);
        error = true;
    }
    else if (!peer->key_server) {
        MKA_LOG_ERROR("KaY/%i: Received DISTRIBUTED SAK from a non Key Server peer. Discarded.", bus);
        error = true;
    }
    else if (!MKA_sci_equal(&ctx->key_server_sci, &peer->sci)) {
        MKA_LOG_ERROR("KaY/%i: Received DISTRIBUTED SAK from a non elected Key Server. Discarded.", bus);
        error = true;
    }
    else if (MKA_DIST_SAK_LEN_EMPTY == body_len) {
        if (mka_is_cipher_acceptable(bus, MKA_CS_NULL)) {
            MKA_LOG_DEBUG1("KaY/%i: Peer transmits DIST SAK with empty body. Silently ignored.", bus);
        }
        else {
            MKA_LOG_WARNING("KaY/%i: Peer transmits DIST SAK with empty body, but NULL cipher is not in the preferred list. This is an error.", bus);
            error = true;
        }
        continue_process = false;
    }
    else if (MKA_MACSEC_NOT_IMPLEMENTED == ctx->macsec_capable) {
        MKA_LOG_ERROR("KaY/%i: Received DISTRIBUTED SAK but I do not implement MACSEC. Discarded.", bus);
        error = true;
    }
    else if (MKA_mi_equal(current_sak->identifier.mi, peer->mi) && (current_sak->identifier.kn == incoming_kn)) {
        MKA_LOG_DEBUG1("KaY/%i: Remote Key Server installing known SAK key. Silently ignoring.", bus);
        continue_process = false;
    }
    else if (mka_sak_nonce_protection(bus, peer->mi, incoming_kn, 1ULL)) {
        continue_process = false;
    }
    else {
        participant->advertise_macsec_desired = true;
        mka_set_mode(bus, MKA_SECURED);
        sak = &participant->new_sak;
        memset(sak, 0, sizeof(t_MKA_sak));

        if (MKA_DIST_SAK_LEN_DEFAULT != body_len) {
            t_MKA_ciphsuite cipher = MKA_NBTOQ(body_past_kn);

            sak_wrapped = &body_past_kn[sizeof(t_MKA_ciphsuite)];

            if (!mka_is_cipher_acceptable(bus, cipher)) {
                MKA_LOG_WARNING("KaY/%i: Key server is requesting a non-preferred cipher suite 0x%08lX%08lX. Discarded.",
                    bus, (uint32_t)(cipher >> 32U), (uint32_t)cipher);
                error = true;
            }
            else if ((MKA_CS_ID_GCM_AES_128 == cipher) || (MKA_CS_ID_GCM_AES_XPN_128 == cipher)) {
                sak_wrapped_len = MKA_KEY_128BIT_WRAPPED;
                sak->cipher = cipher;
            }
            else if ((MKA_CS_ID_GCM_AES_256 == cipher) || (MKA_CS_ID_GCM_AES_XPN_256 == cipher)) {
                sak_wrapped_len = MKA_KEY_256BIT_WRAPPED;
                sak->cipher = cipher;
            }
            else {
                MKA_LOG_ERROR("KaY/%i: Key server is requesting unknown cipher suite 0x%08lX%08lX. Discarded.",
                    bus, (uint32_t)(cipher >> 32U), (uint32_t)cipher);
                error = true;
            }
        }
        else if (!mka_is_cipher_acceptable(bus, MKA_CS_ID_GCM_AES_128)) {
            MKA_LOG_WARNING("KaY/%i: Key server is requesting default but non-preferred cipher suite. Discarded.", bus);
            error = true;
        }
        else {
            sak_wrapped_len = MKA_KEY_128BIT_WRAPPED;
            sak_wrapped = body_past_kn;
            sak->cipher = MKA_CS_ID_GCM_AES_128;
        }
    }

    // error case
    if (!continue_process || error || (NULL == sak) || (NULL == sak_wrapped)) {
        // No action
    }
    else if (!MKA_UnwrapKey(&participant->kek, sak_wrapped, sak_wrapped_len, &sak_holder)) {
        MKA_LOG_ERROR("KaY/%i: Received DISTRIBUTED SAK, unable to unwrap SAK key. Discarded.", bus);
        error = true;
    }
    else {
        memcpy(sak->identifier.mi, peer->mi, sizeof(peer->mi));
        sak->identifier.kn = incoming_kn;
        sak->secy_reference = MKA_SECY_InstallKey(bus, &sak_holder, &sak->identifier, true, true);
        // Clear SAK from RAM
        memset(&sak_holder, 0, sizeof(sak_holder));

        if (NULL == sak->secy_reference) {
            MKA_LOG_ERROR("KaY/%i: Received DISTRIBUTED SAK but SECY is unable to install. Discarded.", bus);
            memset(sak, 0, sizeof(t_MKA_sak));
            error = true;
        }
        else {
            sak->creation = mka_tick_time_ms;
            sak->next_pn = 1ULL;
            sak->association_number = content->distributed_an;
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            sak->confidentiality_offset = (t_MKA_confidentiality_offset)content->confidentiality_offset;
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
            participant->conf_offset = (t_MKA_confidentiality_offset)content->confidentiality_offset;

            participant->cipher = sak->cipher;

            // Update CP with new SAK, start transitions
            MKA_CP_SetCipherSuite(bus, sak->cipher);
            MKA_CP_SetCipherOffset(bus, sak->confidentiality_offset);
            MKA_CP_SetDistributedKI(bus, &sak->identifier);
            MKA_CP_SetDistributedAN(bus, sak->association_number);
            MKA_CP_SetServerTransmitting(bus, false);
            MKA_CP_SetAllReceiving(bus, false);
            MKA_CP_SignalNewSAK(bus);
        }
    }

    return !error;
}

bool mka_encode_distributed_sak(t_MKA_bus bus, uint8_t *packet, uint32_t *length)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;

    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_dist_sak *const param = (t_mka_dist_sak*)&packet[*length];
    uint8_t* const param_past_header = &packet[(*length) + sizeof(t_mka_dist_sak)];
    bool const empty = (MKA_CS_NULL == participant->cipher) && (participant->is_key_server);
    bool const present = empty || (MKA_SAK_KS_DISTRIBUTING == participant->sak_state);
    bool const header = (MKA_CS_ID_GCM_AES_128 != participant->cipher);
    uint32_t const wrapped_size = (
            ((MKA_CS_ID_GCM_AES_XPN_256 == participant->cipher) ||
                (MKA_CS_ID_GCM_AES_256 == participant->cipher)) ? 
                    (uint32_t)MKA_KEY_256BIT_WRAPPED : (uint32_t)MKA_KEY_128BIT_WRAPPED);
    t_MKA_sak const*const sak = (NULL != participant->new_sak.secy_reference) ?
                    (&participant->new_sak) : (&participant->current_sak);
    bool continue_process = true;

    // NOTE: Standard does not clearly states WHEN "dist sak" is transmitted or not without MACSEC.
    // However, it considers the possibility of "dist sak" being transmited without MACSEC, just imposes
    // its body length to be 0. Transmitting it would be redundant, so I'm not transmitting it for now.
    // If we decide to transmit it in the future, the implementation is here.
    if (!MKA_active_global_config->transmit_empty_dist_sak) {
        // No action: never encoded empty
    }
    else if (!present || !empty) {
        // No action

    } // present and empty, case no space available
    else if (!mka_frame_account_space(length, sizeof(t_mka_param_generic))) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to DIST SAK(1) encoding error.", bus);
        continue_process = false;

    } // present and empty
    else {
        memset(param, 0, sizeof(t_mka_param_generic));
        param->type = PARAMETER_DISTRIBUTED_SAK;
    }

    if (!present || empty || header) {
        // No action

    } // present and without header, case no space available
    else if (!mka_frame_account_space(length, sizeof(t_mka_dist_sak) + wrapped_size)) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to DIST SAK(2) encoding error.", bus);
        continue_process = false;

    } // present and empty
    else {
        memset(param, 0, sizeof(t_mka_dist_sak));
        param->type = PARAMETER_DISTRIBUTED_SAK;
        param->distributed_an = sak->association_number;
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        param->confidentiality_offset = (uint_t)sak->confidentiality_offset;
        param->length = 0U;
        param->length_cont = (uint8_t)wrapped_size +
                (uint8_t)((uint8_t)sizeof(t_mka_dist_sak) - (uint8_t)sizeof(t_mka_param_generic));
        param->key_number = MKA_HTONL(sak->identifier.kn);
        memcpy(param_past_header, participant->new_sak_wrapped, wrapped_size);
    }

    if (!present || empty || !header) {
        // No action

    } // present and with header, case no space available
    else if (!mka_frame_account_space(length, sizeof(t_mka_dist_sak) + sizeof(t_MKA_ciphsuite) + wrapped_size)) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to DIST SAK(3) encoding error.", bus);
        continue_process = false;

    } // present and empty
    else {
        memset(param, 0, sizeof(t_mka_dist_sak));
        param->type = PARAMETER_DISTRIBUTED_SAK;
        param->distributed_an = sak->association_number;
        //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
        param->confidentiality_offset = (uint_t)sak->confidentiality_offset;
        param->length = 0U;
        param->length_cont = (uint8_t)wrapped_size + (uint8_t)sizeof(t_MKA_ciphsuite) +
                (uint8_t)((uint8_t)sizeof(t_mka_dist_sak) - (uint8_t)sizeof(t_mka_param_generic));
        param->key_number = MKA_HTONL(sak->identifier.kn);
        param_past_header[0] = (uint8_t)((participant->cipher >> 56U) & 0xFFU);
        param_past_header[1] = (uint8_t)((participant->cipher >> 48U) & 0xFFU);
        param_past_header[2] = (uint8_t)((participant->cipher >> 40U) & 0xFFU);
        param_past_header[3] = (uint8_t)((participant->cipher >> 32U) & 0xFFU);
        param_past_header[4] = (uint8_t)((participant->cipher >> 24U) & 0xFFU);
        param_past_header[5] = (uint8_t)((participant->cipher >> 16U) & 0xFFU);
        param_past_header[6] = (uint8_t)((participant->cipher >>  8U) & 0xFFU);
        param_past_header[7] = (uint8_t)((participant->cipher       ) & 0xFFU);
        memcpy(&param_past_header[sizeof(t_MKA_ciphsuite)], participant->new_sak_wrapped, wrapped_size);
    }

    return continue_process;
}

bool mka_handle_sak_use(t_MKA_bus bus, uint8_t const*param, uint32_t body_len, uint32_t xpn_o_high, uint32_t xpn_l_high)
{
    // TODO: handle plain_tx // plain_rx!
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer*const peer = &participant->peer;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_sak_use const*const content = (t_mka_sak_use const*)param;
    t_MKA_sak* osak = NULL;
    t_MKA_sak* lsak = NULL;
    t_MKA_sak const* new_sak = NULL;
    bool new_sak_rx = false;
    bool new_sak_tx = false;
    bool peer_pn_exhaustion = false;
    bool const is_cipher_xpn = mka_is_cipher_xpn(participant->cipher);
    t_MKA_pn const exhaustion_threshold = is_cipher_xpn ?  MKA_XPN_EXHAUSTION : MKA_PN_EXHAUSTION;
    bool continue_process = true;

    t_MKA_sak const*const newest_sak = (NULL != participant->new_sak.secy_reference) ?
                    (&participant->new_sak) : (&participant->current_sak);

    if (MKA_PEER_LIVE != peer->state) {
        MKA_LOG_WARNING("KaY/%i: Received SAK USE from non-live peer. Ignored.", bus);
        continue_process = false;
    }
    else if (0U == body_len) {
        if (MKA_CS_NULL == participant->cipher) {
            MKA_LOG_DEBUG1("KaY/%i: Peer transmits SAK USE with empty body. Silently ignored.", bus);
        }
        else {
            MKA_LOG_ERROR("KaY/%i: Peer does not support MACSEC, but this hasn't been negotiated.", bus);
            continue_process = false;
        }
    }
    else if (40U > body_len) {
        MKA_LOG_ERROR("KaY/%i: Received MKPDU with incorrect SAK USE body_len, expected >=40, got %i.",
            bus, body_len);
        continue_process = false;
    }
    else {
        lsak = mka_find_key(bus, content->latest_kmi, MKA_NTOHL(content->latest_kn));
        osak = mka_find_key(bus, content->old_kmi, MKA_NTOHL(content->old_kn));

        if ((NULL == osak) || (NULL == osak->secy_reference)) {
            // Nothing
        }
        else if (content->oan != osak->association_number) {
            MKA_LOG_ERROR("KaY/%i: Received SAK USE with OAN not matching our key. Discarded.", bus);
            continue_process = false;
        }
        else if ((0U == /* NOTE! 0 is endian-invariant! */ content->old_laccpn) &&
                 (!is_cipher_xpn || (0U == xpn_o_high))) {
            MKA_LOG_ERROR("KaY/%i: Received SAK USE with 0 as Old Key Lowest Acceptable PN. Discarded.", bus);
            continue_process = false;
        }
        else {
            osak->next_pn = ((t_MKA_ciphsuite)xpn_o_high) << 32U;
            osak->next_pn |= MKA_NTOHL(content->old_laccpn);
            if ((content->delay_protect > 0U) && (NULL != osak->rxsa)) {
                MKA_SECY_ReceiveSA_UpdateNextPN(bus, osak->rxsa, osak->next_pn);
            }
            new_sak = (osak == &participant->new_sak) ? osak : NULL;
        }

        if ((NULL == lsak) || (NULL == lsak->secy_reference)) {
            // Nothing
        }
        else if (content->lan != lsak->association_number) {
            MKA_LOG_ERROR("KaY/%i: Received SAK USE with LAN not matching our key. Discarded.", bus);
            continue_process = false;
        }
        else if ((0U == /* NOTE! 0 is endian-invariant! */ content->latest_laccpn) &&
                 (!is_cipher_xpn || (0U == xpn_l_high))) {
            MKA_LOG_ERROR("KaY/%i: Received SAK USE with 0 as Latest Key Lowest Acceptable PN. Discarded.", bus);
            continue_process = false;
        }
        else {
            lsak->next_pn = ((t_MKA_ciphsuite)xpn_l_high) << 32U;
            lsak->next_pn |= MKA_NTOHL(content->latest_laccpn);
            if ((content->delay_protect > 0U) && (NULL != lsak->rxsa)) {
                MKA_SECY_ReceiveSA_UpdateNextPN(bus, lsak->rxsa, lsak->next_pn);
            }
            new_sak = (lsak == &participant->new_sak) ? osak : NULL;
        }

        if (osak == newest_sak) {
            new_sak = osak;
            new_sak_rx = (content->orx > 0U);
            new_sak_tx = (content->otx > 0U);
            peer_pn_exhaustion = (osak->next_pn >= exhaustion_threshold);
        }
        else if (lsak == newest_sak) {
            new_sak = lsak;
            new_sak_rx = (content->lrx > 0U);
            new_sak_tx = (content->ltx > 0U);
            peer_pn_exhaustion = (lsak->next_pn >= exhaustion_threshold);
        }
        else if ((NULL == osak) && (NULL == lsak)) {
            MKA_LOG_INFO("KaY/%i: Received SAK USE with no known key. Discarded.", bus);
            continue_process = false;
        }
        else {
            // No action
        }

        peer->transmits_sak_use = continue_process;
    }

    if (!continue_process) {
        // No action

    } // No SAK
    else if (NULL == new_sak) {
        peer_pn_exhaustion = (participant->current_sak.next_pn >= exhaustion_threshold);

    } // Case we are key server and peer is receiving with new SAK (distributed to him)
    else if (participant->is_key_server && new_sak_rx) {
        MKA_LOG_DEBUG2("KaY/%i: Peer is now receiving with distributed SAK.", bus);
        MKA_CP_SetAllReceiving(bus, true);
        participant->sak_state = (MKA_SAK_KS_DISTRIBUTING == participant->sak_state) ?
                                        MKA_SAK_INSTALLED : participant->sak_state;

    } // Case we are not key server, and peer is transmitting with new SAK (distributed to us)
    else if ((!participant->is_key_server) && new_sak_tx) {
        MKA_LOG_DEBUG2("KaY/%i: Key Server is now transmitting with new SAK.", bus);
        MKA_CP_SetServerTransmitting(bus, true);
        participant->sak_state = MKA_SAK_INSTALLED;

    } // Something else
    else {
        // No further action
    }

    // Handle PN exhaustion
    if (peer_pn_exhaustion && participant->is_key_server && (MKA_SAK_INSTALLED == participant->sak_state)) {
        MKA_LOG_INFO("KaY/%i: Peer reached PN exhaustion.", bus);
        // Transition MKA_SAK_INSTALLED -> MKA_SAK_KS_DO_GENERATE
        participant->sak_state = (MKA_SAK_INSTALLED == participant->sak_state) ?
                                        MKA_SAK_KS_DO_GENERATE : participant->sak_state;
    }

    // continue
    return continue_process;
}

bool mka_encode_sak_use(t_MKA_bus bus, uint8_t *packet, uint32_t *length)
{
    t_mka_kay *const ctx = &mka_kay[bus];
    t_mka_participant *const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    uint8_t lan = 0U;
    bool    ltx = false;
    bool    lrx = false;
    uint8_t oan = 0U;
    bool    otx = false;
    bool    orx = false;
    t_MKA_sak const* old = mka_get_old(bus, &oan, &otx, &orx);
    t_MKA_sak const*const latest = mka_get_latest(bus, &lan, &ltx, &lrx);

    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_sak_use *const param = (t_mka_sak_use*)&packet[*length];
    // Transmitted when a SAK is in use
    bool const present_empty = ((MKA_PEER_LIVE == peer->state) && \
                            (MKA_MACSEC_NOT_IMPLEMENTED == participant->advertise_macsec_capability));
    bool const present_filled = (!present_empty) && (MKA_PEER_LIVE == peer->state) && (\
            ((NULL != old) && (old->secy_reference)) || ((NULL != latest) && (NULL != latest->secy_reference)));
    bool const is_cipher_xpn = mka_is_cipher_xpn(participant->cipher);
    t_MKA_pn const exhaustion_threshold = is_cipher_xpn ?  MKA_XPN_EXHAUSTION : MKA_PN_EXHAUSTION;
    bool continue_process = true;

    // NOTE: Mechanism to detect CP state RETIRE from KaY is really limited. Maybe the way is comparing
    // oki/lki, but these are only read when encoding SAK uses. Therefore I'm going to transition KaY SAK
    // from new_sak to current_sak here. This is not ideal, but I used to do it on calls to deleteSa() with invalid
    // keys (first time), and that strategy seems even worse. It even has side effects when unauthenticated allowed is immediate.
    if ((latest == NULL) && (old == &participant->new_sak)) {
        memcpy(&participant->current_sak, &participant->new_sak, sizeof(t_MKA_sak));
        memset(&participant->new_sak, 0, sizeof(t_MKA_sak));
        old = &participant->current_sak; // update pointer after rotating
    }

    // NOTE: Standard does not clearly states WHEN "sak use" is to be transmitted without MACSEC.
    // However, it considers the possibility of "sak use" being transmited without MACSEC, just imposes
    // its body length to be 0. Transmitting it would be redundant, so I'm not transmitting it.
    // NOTE: Wireshark doesn't understand this particular use case of this parameter.
    // If we decide to transmit it in the future, the implementation is here.
    if (!MKA_active_global_config->transmit_empty_sak_use) {
        // No action: never encoded empty
    }
    else if (!present_empty) {
        // No action
    }
    else if (!mka_frame_account_space(length, sizeof(t_mka_param_generic))) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to SAK USE(1) encoding error.", bus);
        continue_process = false;
    }
    else {
        memset(param, 0, sizeof(t_mka_param_generic));
        param->type = PARAMETER_SAK_USE;
        param->plain_tx = BOOL_CAST(true);
        param->plain_rx = BOOL_CAST(true);
    }

    if (!present_filled) {
        // No action
    }
    else if (!mka_frame_account_space(length, sizeof(t_mka_sak_use))) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to SAK USE(2) encoding error.", bus);
        continue_process = false;
    }
    else {
        bool pn_exhaustion = false;

        memset(param, 0, sizeof(t_mka_sak_use));
        param->type = PARAMETER_SAK_USE;
        param->length_cont = (uint8_t)sizeof(t_mka_sak_use) - (uint8_t)sizeof(t_mka_param_generic);
        param->plain_tx = BOOL_CAST(!MKA_CP_GetProtectFrames(bus));
        param->plain_rx = BOOL_CAST(MKA_VALIDATE_STRICT != MKA_CP_GetValidateFrames(bus));
        param->delay_protect = BOOL_CAST(ctx->macsec_delay_protect);

        // Non-null only when security association exists
        // hostapd compatibility in unused SA slot
        if ((NULL == old) || (NULL == old->rxsa) || (NULL == old->txsa)) {
            param->old_laccpn = MKA_HTONL(UNUSED_SA_PN);
        }
        else {
            uint32_t next_pn = (uint32_t)old->txsa->next_pn;

            param->orx = BOOL_CAST(orx);
            param->otx = BOOL_CAST(otx);
            param->oan = oan;
            memcpy(param->old_kmi, old->identifier.mi, MKA_MI_LENGTH);
            param->old_kn = MKA_HTONL(old->identifier.kn);
            param->old_laccpn = MKA_HTONL(next_pn);

            pn_exhaustion = (old == &participant->current_sak) && \
                    (old->txsa->next_pn >= exhaustion_threshold);
        }

        // Non-null only when security association exists
        // hostapd compatibility in unused SA slot
        if ((NULL == latest) || (NULL == latest->rxsa) || (NULL == latest->txsa)) {
            param->latest_laccpn = MKA_HTONL(UNUSED_SA_PN);
        }
        else {
            uint32_t next_pn = (uint32_t)latest->txsa->next_pn;

            param->lrx = BOOL_CAST(lrx);
            param->ltx = BOOL_CAST(ltx);
            param->lan = lan;
            memcpy(param->latest_kmi, latest->identifier.mi, MKA_MI_LENGTH);
            param->latest_kn = MKA_HTONL(latest->identifier.kn);
            param->latest_laccpn = MKA_HTONL(next_pn);

            pn_exhaustion = false; // No exhaustion during SAK transition
        }

        if (participant->is_key_server && (MKA_SAK_INSTALLED == participant->sak_state) && pn_exhaustion) {
            MKA_LOG_INFO("KaY/%i: Local participant reached PN exhaustion. Generating a new SAK.", bus);
            participant->sak_state = MKA_SAK_KS_DO_GENERATE;
        }

        if (MKA_LINK_UP_REPORTING == ctx->linkup_report) {
            ctx->linkup_report = MKA_LINK_UP_EVENT;
        }
    }

    return continue_process;
}

bool mka_handle_announcement_macsec_ciphersuites(t_MKA_bus bus, uint8_t const*tlv, uint32_t length)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_mka_kay *const ctx = &mka_kay[bus];
    t_mka_participant *const participant = &ctx->participant;
    t_mka_peer *const peer = &participant->peer;
    static const uint32_t prio_max = MKA_ARRAY_SIZE(cfg->impl.cipher_preference);
    bool continue_process = true;

    if (0U != (length%sizeof(t_mka_tlv_macsec_cipher_suites))) {
        MKA_LOG_WARNING("KaY/%i: Malformed announcement MACsec cipher suite.", bus);
        continue_process = false;
    }
    else {
        uint32_t selected_cipher = prio_max;
        uint32_t octet;

        // Iterate announcement ciphers
        for(octet=0U; octet < length; octet += sizeof(t_mka_tlv_macsec_cipher_suites)) {
            //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
            t_mka_tlv_macsec_cipher_suites const*const entry = (t_mka_tlv_macsec_cipher_suites const*)&tlv[octet];
            t_MKA_ciphsuite const cipher = MKA_NTOHQ(entry->ciphersuite);

            // In case cipher is valid, 
            if ((MKA_CS_NULL != cipher) && (MKA_CS_INVALID != cipher)){
                // Iterate our list, searching for a cipher match
                uint32_t cidx; // cipher idx
                for(cidx = 0U; cidx<MKA_ARRAY_SIZE(cfg->impl.cipher_preference); ++cidx) {
                    // No match
                    if (cipher != cfg->impl.cipher_preference[cidx]) {
                        // No action

                    } // Match, this cipher has higher priority than selected one
                    else if (selected_cipher > cidx) {
                        selected_cipher = cidx;
                        //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 2-bit number to 4-value enum is controlled, values match to enum's
                        //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 2-bit number to 4-value enum is controlled, values match to enum's
                        peer->compatible_capability = (t_MKA_macsec_cap)entry->cs_impl_capability;
                        break;

                    } // Match, this cipher has lower priority than selected one
                    else {
                        // No action
                    }
                }
            }
        }

        // Case there is no common cipher with this peer
        if (selected_cipher >= prio_max) {
            peer->compatible_cipher = MKA_CS_INVALID;

        } // Case a common cipher has been found
        else {
            peer->compatible_cipher = cfg->impl.cipher_preference[selected_cipher];
            // Restrict capability for XPN ciphers to confidentiality with 0 offset
            if (mka_is_cipher_xpn(peer->compatible_cipher)) {
                peer->compatible_capability = mka_macsec_cap_min(peer->compatible_capability, MKA_MACSEC_INT_CONF_0);
            }
            peer->compatible_capability = mka_macsec_cap_min(peer->compatible_capability, ctx->macsec_capable);
        }
    }

    return continue_process;
}

bool mka_handle_announcements(t_MKA_bus bus, uint8_t const*param, uint32_t body_len)
{
    bool continue_process = true;
    uint32_t const total_length = body_len + sizeof(t_mka_param_generic);
    uint32_t octet = sizeof(t_mka_param_generic);

    while(continue_process && (octet < total_length)) {
        uint32_t const remaining = total_length - octet;
        uint8_t  tlv_type   = param[octet] >> 1U;
        uint16_t tlv_length = (((uint16_t)param[octet]<<8U)&0x0100U) | (uint16_t)param[octet+1U];

        // Malformed announcement
        if (remaining < 2U) {
            MKA_LOG_WARNING("KaY/%i: Malformed announcement parameter, expecting TLV header.", bus);
            continue_process = false;
        }
        else if (remaining < (2UL + tlv_length)) {
            MKA_LOG_WARNING("KaY/%i: Malformed announcement parameter, TLV length expands outside the parameter area.", bus);
            continue_process = false;
        }
        else if (TLV_MACSEC_CIPHER_SUITES == tlv_type) {
            continue_process = mka_handle_announcement_macsec_ciphersuites(bus, &param[octet+2U], tlv_length);
            octet += 2UL + tlv_length;
        }
        else {
            MKA_LOG_INFO("KaY/%i: Silently ignoring unknown announcement TLV type %i.", bus, tlv_type);
            octet += 2UL + tlv_length;
        }
        
    }

    return continue_process;
}

bool mka_encode_announcements(t_MKA_bus bus, uint8_t *packet, uint32_t *length)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_mka_kay const*const ctx = &mka_kay[bus];
    //t_mka_participant const*const participant = &ctx->participant;
    //t_mka_peer const*const peer = &participant->peer;
    bool continue_process = true;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_param_generic *const content = (t_mka_param_generic*)&packet[*length];
    uint32_t const octet_length_start = (uint32_t)sizeof(t_mka_param_generic) + *length;
    uint32_t octet = octet_length_start;

    memset(content, 0, sizeof(t_mka_param_generic));
    content->header = PARAMETER_ANNOUNCEMENT;
    content->length_cont = 0U; // pending

    // IEEE802.1X-2020 Figure 11-15 announcement encoding
    // IEEE802.1X-2020 11.12 TLV encoding
    // IEEE802.1X-2020 11.12.3 MACsec Cipher Suites TLV
    packet[octet] = TLV_MACSEC_CIPHER_SUITES << 1U;
    ++octet;
    packet[octet] = 0U; // length pending
    ++octet;

    // iterate ciphers configured
    uint32_t cidx; // cipher idx
    for(cidx = 0U; cidx<MKA_ARRAY_SIZE(cfg->impl.cipher_preference); ++cidx) {
        t_MKA_ciphsuite const cipher = cfg->impl.cipher_preference[cidx];
        if ((MKA_CS_NULL != cipher) && (MKA_CS_INVALID != cipher)){
            //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
            t_mka_tlv_macsec_cipher_suites *const entry = (t_mka_tlv_macsec_cipher_suites *)&packet[octet];

            // special treatment for XPN ciphers: conf. offset support (if necessary) can only be 0
            t_MKA_macsec_cap capability = mka_macsec_cap_min(ctx->macsec_capable,
                    mka_is_cipher_xpn(cipher) ? MKA_MACSEC_INT_CONF_0 : MKA_MACSEC_INT_CONF_0_30_50);

            entry->reserved = 0U;
            entry->reserved2 = 0U;
            //lint -e{9030} [MISRA 2012 Rule 10.5, advisory] Casting 4-value enum to 2-bit number is controlled, values match to enum's
            //lint -e{9034} [MISRA 2012 Rule 10.3, required] Casting 4-value enum to 2-bit number is controlled, values match to enum's
            entry->cs_impl_capability = (uint_t)capability;
            entry->ciphersuite = MKA_HTONQ(cipher);

            octet += sizeof(t_mka_tlv_macsec_cipher_suites);
        }
    }

    // adjust first length field
    uint32_t tlv_length = octet - octet_length_start;

    // Case no algorithm is present, OR only default is present OR no MACsec
    if ((2U == tlv_length) || (!cfg->port_capabilities.announcements) ||
            (MKA_MACSEC_NOT_IMPLEMENTED == ctx->macsec_capable)) {
        // Nothing: do not transmit this parameter

    } // Case parameter does not fit
    else if (!mka_frame_account_space(length, sizeof(t_mka_param_generic) + tlv_length)) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to Announcement encoding error.", bus);
        continue_process = false;

    } // Decision taken to transmit announcement parameter
    else {
        // Basic header length
        content->length = (uint8_t)(tlv_length >> 8U) & 0x0FU;
        content->length_cont = (uint8_t)tlv_length & 0xFFU;

        // TLV partial length
        tlv_length -= 2U;
        packet[   octet_length_start] |= (uint8_t)(tlv_length >> 8U) & 1U;
        packet[1U+octet_length_start] |= (uint8_t)tlv_length & 0xFFU;
    }

    return continue_process;
}

bool mka_handle_xpn(t_MKA_bus bus, uint8_t const*param, uint32_t body_len, uint32_t*xpn_o_high, uint32_t*xpn_l_high)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_xpn const*const content = (t_mka_xpn const*)param;
    bool const is_cipher_xpn = mka_is_cipher_xpn(participant->cipher);
    bool continue_process = true;

    // Non-live peer
    if (MKA_PEER_LIVE != peer->state) {
        MKA_LOG_WARNING("KaY/%i: Received XPN from non-live peer. Ignored.", bus);
        continue_process = false;

    } // Invalid parameter length
    else if (body_len < 8U) {
        MKA_LOG_ERROR("KaY/%i: Peer transmitting XPN parameter smaller than minimum of 8 bytes, handling aborted.", bus);
        continue_process = false;

    } // IEE802.1X-2020 Transmitted as zero and ignored on receipt, if the MACsec C.S. does not use XPN.
    else if (!is_cipher_xpn) {
        MKA_LOG_DEBUG1("KaY/%i: Peer transmits XPN, but XPN cipher is not being used. Silently ignored.", bus);

    } // All good, read 32-bit high part of packet numbers
    else {
        *xpn_o_high = MKA_NTOHL(content->old_laccpn_high);
        *xpn_l_high = MKA_NTOHL(content->latest_laccpn_high);
    }

    return continue_process;
}

bool mka_encode_xpn(t_MKA_bus bus, uint8_t *packet, uint32_t *length)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    uint8_t lan = 0U;
    bool    ltx = false;
    bool    lrx = false;
    uint8_t oan = 0U;
    bool    otx = false;
    bool    orx = false;
    t_MKA_sak const*const old = mka_get_old(bus, &oan, &otx, &orx);
    t_MKA_sak const*const latest = mka_get_latest(bus, &lan, &ltx, &lrx);

    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_xpn *const param = (t_mka_xpn*)&packet[*length];
    // Transmitted when a SAK with XPN is in use
    bool const present = (MKA_PEER_LIVE == peer->state) && \
            (MKA_MACSEC_NOT_IMPLEMENTED != participant->advertise_macsec_capability) && \
            (((NULL != old) && (old->secy_reference)) || ((NULL != latest) && (NULL != latest->secy_reference)));
    bool const is_cipher_xpn = mka_is_cipher_xpn(participant->cipher);
    bool continue_process = true;

    if (!MKA_active_global_config->transmit_null_xpn) {
        // No action: never encoded as null
    }
    else if (!present || is_cipher_xpn) {
        // No action

    } // case no space available
    else if (!mka_frame_account_space(length, sizeof(t_mka_xpn))) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to XPN(1) encoding error.", bus);
        continue_process = false;

    } // present and null
    else {
        memset(param, 0, sizeof(t_mka_xpn));
        param->type = PARAMETER_XPN;
        param->length_cont = (uint8_t)sizeof(t_mka_xpn) - (uint8_t)sizeof(t_mka_param_generic);
    }

    // case do not encode parameter
    if (!present || !is_cipher_xpn) {
        // No action

    } // case no space available
    else if (!mka_frame_account_space(length, sizeof(t_mka_xpn))) {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to XPN(2) encoding error.", bus);
        continue_process = false;

    } // parameter must be present, space already accounted for
    else {
        memset(param, 0, sizeof(t_mka_xpn));
        param->type = PARAMETER_XPN;
        param->length_cont = (uint8_t)sizeof(t_mka_xpn) - (uint8_t)sizeof(t_mka_param_generic);

        // Non-null only when security association exists
        if ((NULL != old) && (NULL != old->rxsa) && (NULL != old->txsa)) {
            uint32_t const next_pn_high = (uint32_t)(old->txsa->next_pn >> 32U);
            param->old_laccpn_high = MKA_HTONL(next_pn_high);
        }

        // Non-null only when security association exists
        if ((NULL != latest) && (NULL != latest->rxsa) && (NULL != latest->txsa)) {
            uint32_t const next_pn_high = (uint32_t)(latest->txsa->next_pn >> 32U);
            param->latest_laccpn_high = MKA_HTONL(next_pn_high);
        }
    }

    (void)lan;
    (void)ltx;
    (void)lrx;
    (void)oan;
    (void)otx;
    (void)orx;

    return continue_process;
}

uint8_t const* mka_packet_find_icv(uint8_t const*packet, uint32_t *length)
{
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_eapol_header const*const eapolhdr = EAPOL_FROM_CONST_PACKET(packet);
    uint32_t offset = sizeof(t_MKA_l2_ether_header)+sizeof(t_mka_eapol_header);
    uint32_t const eapol_offset_max = sizeof(t_MKA_l2_ether_header) + sizeof(t_mka_eapol_header) + MKA_HTONS(eapolhdr->body_length);
    uint32_t param_len = 0U;
    uint8_t const* icv;
    uint16_t param_type = 0U;

    if (*length > eapol_offset_max) {
        *length = eapol_offset_max;
    }

    while(((*length - offset) >= (sizeof(t_mka_param_generic) + MKA_ICV_LENGTH)) &&
            (param_type != PARAMETER_NONE) && (param_type != PARAMETER_ICV)) {
        param_type = mka_mkpdu_get_parameter(packet, offset, *length, &param_len);
        offset += sizeof(t_mka_param_generic) + MKA_ALIGN_TO_32BIT(param_len);
    }

    // Cut frame until ICV parameter
    if ((PARAMETER_ICV == param_type) && (*length > offset)) {
        *length = offset;
        icv = (MKA_ICV_LENGTH == param_len) ? &packet[*length - MKA_ICV_LENGTH] : NULL;
    }
    else {
        icv = (*length >= MKA_ICV_LENGTH) ? &packet[*length - MKA_ICV_LENGTH] : NULL;
    }

    return icv;
}

bool mka_encode_icv(t_MKA_bus bus, uint8_t *packet, uint32_t *length)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    uint32_t digest_length = *length;
    uint8_t *const icv_location = &packet[*length];
    bool continue_process = mka_frame_account_space(length, MKA_ICV_LENGTH);

    if (continue_process) {
        continue_process = MKA_ComputeICV(
                /* alg. agility */  MKA_ALGORITHM_AGILITY,
                /* ick          */  &participant->ick,
                /* message      */  packet,
                /* msg_len      */  digest_length,
                /* ICV          */  icv_location
                        );
        if (!continue_process) {
            MKA_LOG_WARNING("KaY/%i: Could not generate ICV for MKPDU.", bus);
        }
    }
    else {
        MKA_LOG_WARNING("KaY/%i: Could not generate MKPDU due to ICV encoding error.", bus);
    }


    return continue_process;
}
