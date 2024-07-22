/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_kay.c
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
 * @file        mka_kay.c
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA KaY implementation
 *
 * @{
 */

/*******************        Includes        *************************/
#include "mka_kay_internal.h"

//lint -estring(9003, mka_dst_address) [MISRA 2012 Rule 8.9, advisory] defining constants on top of the file

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/
t_mka_kay mka_kay[MKA_NUM_BUSES] = {{0}};

MKA_PRIVATE MKA_CONST uint8_t mka_dst_address[] = { 0x01U, 0x80U, 0xC2U, 0x00U, 0x00U, 0x03U };
MKA_PRIVATE uint8_t mka_frame_buffer[MKA_EAPOL_MAX_SIZE] = {0U};

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/

void MKA_KAY_Init(t_MKA_bus bus)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;

    ctx->enable = MKA_ATOMIC_FALSE;
    ctx->enable_request = MKA_ATOMIC_FALSE;
    ctx->role = cfg->kay.actor_role;

    // Case MACSEC disabled
    if ((MKA_MACSEC_NOT_IMPLEMENTED == cfg->kay.macsec_capable) ||
                (MKA_CS_NULL == cfg->impl.cipher_preference[0])) {
        ctx->macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
        ctx->macsec_replay_protect = false;
        ctx->macsec_delay_protect = false;
        ctx->macsec_replay_window = 0U;

    } // MACSEC enabled
    else {
        ctx->macsec_capable = cfg->kay.macsec_capable;
        ctx->macsec_replay_protect = cfg->kay.replay_protect;
        ctx->macsec_replay_window = cfg->kay.replay_protect_wnd;
        ctx->macsec_delay_protect = cfg->kay.delay_protect;
    }

    ctx->new_info = false;

    participant->enable = false;
    ctx->active = false;

    mka_timer_init(&participant->cak_life);
    mka_timer_init(&participant->mka_life);
    mka_timer_init(&participant->hello);

    // L2 management (TODO: move somewhere else when EAP implemented, logon?)
    MKA_ASSERT(MKA_OK == MKA_l2_init(bus, MKA_L2_PROTO_EAPOL), "Cannot start layer 2 interface");
    MKA_ASSERT(MKA_OK == MKA_l2_getLocalAddr(bus, ctx->actor_sci.addr), "Cannot get layer 2 address");
    ctx->actor_sci.port = 1U; // Point to point communication, always use port 1.
    ctx->actor_priority = cfg->kay.actor_priority;

    // Create TX secure channel at startup
    ctx->txsc = MKA_SECY_CreateTransmitSC(bus, &ctx->actor_sci);
    if (NULL == ctx->txsc) {
        MKA_LOG_ERROR("KaY/%i SecY returned NULL Transmit Secure Channel", bus);
    }
}

void MKA_KAY_MainFunctionReception(t_MKA_bus bus)
{
    mka_receive_from_l2(bus);
}

void MKA_KAY_MainFunctionTimers(t_MKA_bus bus)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    // single read of request variable set by user
    bool const enable_req = (MKA_ATOMIC_TRUE == ctx->enable_request);

    // Async. enable transition: was disabled, is now enabled
    if ((MKA_ATOMIC_FALSE == ctx->enable) && enable_req) {
        MKA_LOG_INFO("KaY/%i: KAY enabled for this bus.", bus);
        ctx->enable = MKA_ATOMIC_TRUE;

        MKA_LOGON_SetKayEnabled(bus, true);
    }

    // Async. enable transition: was enabled, is now disabled
    if ((MKA_ATOMIC_TRUE == ctx->enable) && (!enable_req)) {
        MKA_LOG_INFO("KaY/%i: KAY disabled for this bus.", bus);
        ctx->enable = MKA_ATOMIC_FALSE;
        MKA_LOGON_SetKayEnabled(bus, false);
        if (participant->enable) {
            mka_participant_cleanup(bus);
            MKA_LOGON_SignalDeletedMKA(bus);
        }
    }

    // Not enabled
    if ((MKA_ATOMIC_FALSE == ctx->enable) || !participant->enable) {
        // No action

    } // CAK end of life
    else if (mka_timer_expired(&participant->cak_life)) {
        MKA_LOG_INFO("KaY/%i: CAK reached its end of life. Deleting participant.", bus);
        mka_set_mode(bus, MKA_FAILED);

        // Destroy participant as per IEEE8021X 9.14
        MKA_KAY_DeleteMKA(bus);
    }
    else {
        t_mka_peer const*const peer = &participant->peer;
        t_mka_peer *const peer_secondary = &participant->peer_secondary;

        if (mka_timer_expired(&peer->expiry)) {
            MKA_LOG_INFO("KaY/%i: %s peer timed out.", bus,
                (MKA_PEER_POTENTIAL == peer->state) ? "Potential" : "Live");
            mka_peer_cleanup(bus);
        }

        if (mka_timer_expired(&peer_secondary->expiry)) {
            MKA_LOG_INFO("KaY/%i: Secondary peer timed out.", bus);
            mka_timer_stop(&peer_secondary->expiry);
            memset(peer_secondary, 0, sizeof(*peer_secondary));
        }

        if (mka_timer_expired(&participant->mka_life) && (MKA_PEER_NONE == peer->state)) {
            mka_set_mode(bus, MKA_FAILED);
        }

        // no sak generation request
        if (    (MKA_SAK_KS_DO_GENERATE != participant->sak_state) &&
                (MKA_SAK_KS_DO_GENERATE_FIRST != participant->sak_state)) {
            // No action
        }
        else if (!mka_create_new_sak(bus)) {
            // crypto failed

        } // new SAK generated
        else {
            MKA_CP_SetCipherSuite(bus, participant->new_sak.cipher);
            MKA_CP_SetCipherOffset(bus, participant->new_sak.confidentiality_offset);
            MKA_CP_SetDistributedKI(bus, &participant->new_sak.identifier);
            MKA_CP_SetDistributedAN(bus, participant->new_sak.association_number);
            MKA_CP_SetServerTransmitting(bus, false);
            MKA_CP_SetAllReceiving(bus, false);
            MKA_CP_SignalNewSAK(bus);

            participant->sak_state = MKA_SAK_KS_DISTRIBUTING;
            ctx->new_info = true;
        }

        // hello period (TODO: could be disabled after some time)
        if (mka_timer_expired(&participant->hello)) {
            if (ctx->macsec_delay_protect && (MKA_PEER_LIVE == peer->state)) {
                mka_timer_extend(&participant->hello, MKA_active_global_config->bounded_hello_time);
            }
            else if ((participant->hello_rampup_idx < MKA_active_global_config->hello_rampup_number) && (MKA_PEER_LIVE != peer->state)) {
                mka_timer_extend(&participant->hello, MKA_active_global_config->hello_rampup[participant->hello_rampup_idx]);
                ++participant->hello_rampup_idx;
            }
            else {
                mka_timer_extend(&participant->hello, MKA_active_global_config->hello_time);
            }
            // Periodically transmit if we have a peer
            // Periodically transmit if we are to participate (active flag)
            ctx->new_info = (MKA_PEER_NONE != peer->state) || participant->active;
        }
    }
}

void MKA_KAY_MainFunctionTransmission(t_MKA_bus bus)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    t_MKA_bus_info *bus_info = &ctx->state_info;
    t_MKA_bus_info new_bus_info = {MKA_STATUS_UNDEFINED, {{0U}, 0U}};

    if ((MKA_ATOMIC_TRUE == ctx->enable) && participant->enable && ctx->new_info) {
        ctx->new_info = false;
        mka_transmit_mkpdu(bus);

        if (MKA_LINK_UP_EVENT == ctx->linkup_report) {
            MKA_BUS_EVENT(bus, MKA_EVENT_LINKUP);
            ctx->linkup_report = MKA_LINK_UP;
        }
    }

    /*********** Update bus status **********/
    // Bus is disabled
    if (MKA_ATOMIC_FALSE == ctx->enable) {
        new_bus_info.status = MKA_STATUS_UNDEFINED;

    } // Bus is enabled, but no participant (link down!)
    else if (!participant->enable) {
        new_bus_info.status = MKA_STATUS_WAITING_PEER_LINK;

    } // Secure channel created
    else if (NULL != ctx->rxsc) {
        new_bus_info.status = MKA_STATUS_MACSEC_RUNNING;
        (void)memcpy(&new_bus_info.peer_sci, &peer->sci, sizeof(peer->sci));

    } // No secure channel, peer is known, negotiation ongoing
    else if ((MKA_PEER_LIVE == peer->state) || (MKA_PEER_POTENTIAL == peer->state)) {
        new_bus_info.status = MKA_STATUS_IN_PROGRESS;
        (void)memcpy(&new_bus_info.peer_sci, &peer->sci, sizeof(peer->sci));

    } // No secure channel, no peer, received frames with invalid ICV
    else if (participant->invalid_icv_received) {
        new_bus_info.status = MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER;

    } // No secure channel, no peer; no invalid ICV received
    else {
        new_bus_info.status = MKA_STATUS_WAITING_PEER;
    }

    // Fatal error ocurred with secy, reset bus
    if ((MKA_ATOMIC_TRUE == ctx->enable) && ctx->secy_error_occurred) {
        MKA_LOG_WARNING("KaY/%i: Resetting participant after SecY fatal error occurred.", bus);
        mka_new_participant_mi(bus);
        ctx->secy_error_occurred = false; // consume error
    }

    if (0 != memcmp(bus_info, &new_bus_info, sizeof(new_bus_info))) {
        MKA_CRITICAL_ENTER();
        (void)memcpy(bus_info, &new_bus_info, sizeof(new_bus_info));
        MKA_CRITICAL_LEAVE();
    }
}

void MKA_KAY_Participate(t_MKA_bus bus, bool enable)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;

    participant->active = enable;
    if (enable) {
        if(MKA_active_global_config->hello_rampup_number > 0U) {
            mka_timer_start(&participant->hello, MKA_active_global_config->hello_rampup[0]);
            participant->hello_rampup_idx = 1U;
        }
        else {
            mka_timer_start(&participant->hello, MKA_active_global_config->hello_time);
        }
        mka_timer_start(&participant->mka_life, MKA_active_global_config->life_time);
        ctx->new_info = true;
    }
    else {
        mka_timer_stop(&participant->mka_life);
    }
}

void MKA_KAY_SignalNewInfo(t_MKA_bus bus)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    ctx->new_info = true;
}

void MKA_KAY_SetEnable(t_MKA_bus bus, bool enable)
{
    t_mka_kay*const ctx = &mka_kay[bus];

    ctx->enable_request = enable ? MKA_ATOMIC_TRUE : MKA_ATOMIC_FALSE;
}

bool MKA_KAY_GetEnable(t_MKA_bus bus)
{
    return MKA_ATOMIC_TRUE == mka_kay[bus].enable;
}

bool MKA_KAY_CreateMKA(t_MKA_bus bus, t_MKA_ckn const*ckn, t_MKA_key const*cak, t_MKA_key const*kek,
                                t_MKA_key const*ick, void const*authdata, uint32_t life)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    bool result = true;

    (void)authdata;

    // Instance not enabled
    if (MKA_ATOMIC_FALSE == ctx->enable) {
        MKA_LOG_WARNING("KaY/%i: Attempt to create a participant in a disabled bus.", bus);
        result = false;

    } // One participant already exists (this implementation is limited to one)
    else if (participant->enable) {
        MKA_LOG_WARNING("KaY/%i: Attempt to create a second participant.", bus);
        result = false;
    }
    else {
        MKA_LOG_INFO("KaY/%i: Creating participant.", bus);
        memcpy(&participant->ckn, ckn, sizeof(t_MKA_ckn));
        memcpy(&participant->cak, cak, sizeof(t_MKA_key));
        memcpy(&participant->kek, kek, sizeof(t_MKA_key));
        memcpy(&participant->ick, ick, sizeof(t_MKA_key));
        // Infinite time (pre-shared key)
        if (MKA_TIMER_MAX == life) {
            mka_timer_stop(&participant->cak_life);
        } // Finite time (EAP negotiated)
        else {
            mka_timer_start(&participant->cak_life, life);
        }

        participant->enable = true;
        participant->active = true;
        participant->cipher = MKA_CS_INVALID; //cfg->impl.cipher_preference[0];
        participant->conf_offset = cfg->impl.conf_offset_preference;
        mka_new_participant_mi(bus);

        if(MKA_active_global_config->hello_rampup_number > 0U) {
            mka_timer_start(&participant->hello, MKA_active_global_config->hello_rampup[0]);
            participant->hello_rampup_idx = 1U;
        }
        else {
            mka_timer_start(&participant->hello, MKA_active_global_config->hello_time);
        }
    }

    return result;
}

void MKA_KAY_DeleteMKA(t_MKA_bus bus)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;

    // Instance not enabled
    if (MKA_ATOMIC_FALSE == ctx->enable) {
        MKA_LOG_WARNING("KaY/%i: Attempt to delete a participant in a disabled bus.", bus);

    } // No participant exists (this implementation is limited to one)
    else if (!participant->enable) {
        MKA_LOG_WARNING("KaY/%i: Attempt to delete a non-existing participant.", bus);
    }
    else {
        mka_participant_cleanup(bus);
        MKA_LOGON_SignalDeletedMKA(bus);
    }
}

bool MKA_KAY_GetProtectFrames(t_MKA_bus bus)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    // Frame protection ON <=> MACSEC enable
    return (MKA_MACSEC_NOT_IMPLEMENTED != participant->advertise_macsec_capability);
}

t_MKA_validate_frames MKA_KAY_GetValidateFrames(t_MKA_bus bus)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    // Validate frames ON <=> MACSEC enable
    return (MKA_MACSEC_NOT_IMPLEMENTED != participant->advertise_macsec_capability)
        ? MKA_VALIDATE_STRICT : MKA_VALIDATE_DISABLED;
}

bool MKA_KAY_GetReplayProtect(t_MKA_bus bus)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    return ctx->macsec_replay_protect;
}

uint32_t MKA_KAY_GetReplayWindow(t_MKA_bus bus)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    return ctx->macsec_replay_window;
}

bool mka_update_txsa_pn(t_MKA_bus bus)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    bool continue_process = true;

    if (NULL == participant->new_sak.txsa) {
        // No action
    }
    else if (MKA_OK != MKA_SECY_TransmitSA_UpdateNextPN(bus, participant->new_sak.txsa)) {
        continue_process = false;
    }
    else {
        // OK
    }

    if (NULL == participant->current_sak.txsa) {
        // No action
    }
    else if (MKA_OK != MKA_SECY_TransmitSA_UpdateNextPN(bus, participant->current_sak.txsa)) {
        continue_process = false;
    }
    else {
        // OK
    }

    return continue_process;
}

void mka_transmit_mkpdu(t_MKA_bus bus)
{
    t_mka_kay *const ctx = &mka_kay[bus];
    t_mka_participant *const participant = &ctx->participant;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_MKA_l2_ether_header *const ethhdr = ETHHDR_FROM_PACKET(mka_frame_buffer);
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_eapol_header *const eapolhdr = EAPOL_FROM_PACKET(mka_frame_buffer);
    bool continue_process = true;
    uint32_t ethernet_len = 0U;

    // 14 bytes Layer 2 header (necessary for ICV calculation!)
    memcpy(ethhdr->dst, mka_dst_address, MKA_L2_ADDR_SIZE);
    MKA_ASSERT(MKA_OK == MKA_l2_getLocalAddr(bus, ethhdr->src), "Cannot get layer 2 address");
    ethhdr->type = MKA_HTONS(MKA_L2_PROTO_EAPOL);
    ethernet_len += sizeof(t_MKA_l2_ether_header);

    // 4 bytes EAPOL header
    eapolhdr->version = MKA_EAPOL_VERSION;
    eapolhdr->type = MKA_EAPOL_TYPE_MKAPDU;
    eapolhdr->body_length = MKA_HTONS(0U); // TODO to be filled later
    ethernet_len += sizeof(t_mka_eapol_header);

    ++participant->mn;

    // Update PN for active security associations
    if (!mka_update_txsa_pn(bus)) {
        MKA_LOG_ERROR("KaY/%i: Cannot get transmission PN. Skip sending frame", bus);
        continue_process = false;
    }

    {
        uint8_t i;
        static bool(*const encoders[])(t_MKA_bus bus, uint8_t *packet, uint32_t *length) = {
            mka_encode_basic_parameter_set,
            mka_encode_peer_list,
            mka_encode_sak_use,
            mka_encode_distributed_sak,
            mka_encode_announcements,
            mka_encode_xpn,
            mka_encode_icv
        };

        for(i=0U; (i<MKA_ARRAY_SIZE(encoders)) && continue_process; ++i) {
            // Update body length right before computing ICV
            if (mka_encode_icv == encoders[i]) {
                uint16_t body_length = (uint16_t)ethernet_len + (uint16_t)MKA_ICV_LENGTH;
                body_length -= (uint16_t)((uint16_t)sizeof(t_MKA_l2_ether_header) +
                                            (uint16_t)sizeof(t_mka_eapol_header));
                eapolhdr->body_length = MKA_HTONS(body_length);
            }

            continue_process = encoders[i](bus, mka_frame_buffer, &ethernet_len);

            // Alignment to 4 after EAPOL header (18 bytes, modulo target is +2)
            while(continue_process && (2U != (ethernet_len & 3U))) {
                if (ethernet_len < MKA_EAPOL_MAX_SIZE) {
                    mka_frame_buffer[ethernet_len] = 0U; // padding with zeros
                    ++ethernet_len;
                }
                else {
                    continue_process = false;
                }
            }
        }
    }

    if (continue_process) {
        if (MKA_OK != MKA_l2_transmit(bus, mka_frame_buffer, ethernet_len)) {
            --participant->mn;
            MKA_LOG_WARNING("KaY/%i: Layer 2 module rejecting transmission of MKPDU frame.", bus);
        }
    }
}

void mka_handle_mkpdu(t_MKA_bus bus, uint8_t const*packet, uint32_t length)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer*const peer = &participant->peer;
    t_mka_peer_state initial_peer_state = peer->state;
    uint32_t offset = sizeof(t_MKA_l2_ether_header)+sizeof(t_mka_eapol_header);
    bool main_peer = true; // secondary peer: quick renegotiation after peer resets its MI
    bool header_presence[256U];
    bool continue_process;
    uint16_t param_type = 0U;
    // sak use processing delayed
    uint32_t sak_use_offset = 0U;
    uint32_t sak_use_length = 0U;
    // dist sak processing delayed
    uint32_t dist_sak_offset = 0U;
    uint32_t dist_sak_length = 0U;

    // Basic Parameter Set is always first
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_basic_parameter_set const*const bps = (t_mka_basic_parameter_set const*)&packet[offset];
    offset += sizeof(t_mka_param_generic) + MKA_ALIGN_TO_32BIT(((uint32_t)bps->length << 8U) + (uint32_t)bps->length_cont);
    continue_process = mka_handle_basic_parameter_set(bus, bps);
    main_peer = MKA_mi_equal(peer->mi, bps->actor_mi);

    /* Re-evaluate in what remote list we are listed, based on the processing
     * of potential/live peer lists below, which must be populated right after
     * basic parameter set. */
    peer->remote_state = MKA_PEER_NONE;

    memset(header_presence, 0, sizeof(header_presence));

    while(((length - offset) > (sizeof(t_mka_param_generic) + MKA_ICV_LENGTH)) &&
            (param_type <= PARAMETER_ICV) && continue_process) {
        uint32_t param_len = 0U;
        uint16_t const previous_param_type = param_type;
        param_type = mka_mkpdu_get_parameter(packet, offset, length, &param_len);

        if (param_type > PARAMETER_ICV) {
            // We are done
        }
        else if (header_presence[param_type]) {
            MKA_LOG_DEBUG0("KaY/%i: Received MKPDU with duplicated header [%i]. Ignored", bus, param_type);
        }
        else if (param_type < previous_param_type) {
            MKA_LOG_ERROR("KaY/%i: Received MKPDU violating parameter order from IEEE802.1X 11.11.3. Discarded.", bus, param_type);
            continue_process = false;
        }
        else {
            switch(param_type) {
            case PARAMETER_LIVE_PEER_LIST:
                continue_process = mka_handle_peer_list(bus, &packet[offset], param_len, main_peer, MKA_PEER_LIVE);
                main_peer = MKA_mi_equal(peer->mi, bps->actor_mi); // re-evaluate
                break;
            case PARAMETER_POTENTIAL_PEER_LIST:
                continue_process = mka_handle_peer_list(bus, &packet[offset], param_len, main_peer, MKA_PEER_POTENTIAL);
                main_peer = MKA_mi_equal(peer->mi, bps->actor_mi); // re-evaluate
                break;
            case PARAMETER_SAK_USE:
                // if we are not key server, a SAK USE parameter could be meaningless unless
                // we process first the DISTRIBUTED SAK parameter.
                // delay processing of SAK use to cover this case
                sak_use_offset = offset;
                sak_use_length = param_len;
                break;

            case PARAMETER_DISTRIBUTED_SAK:
                // if we are key client, a DIST SAK parameter could come too soon before cipher negotiation takes place
                // it is necessary to parse ANNOUNCEMENT first, then perform cipher suite negotiation, and then handle DIST SAK
                dist_sak_offset = offset;
                dist_sak_length = param_len;
                break;

            case PARAMETER_ANNOUNCEMENT:
                if (main_peer) {
                    continue_process = mka_handle_announcements(bus, &packet[offset], param_len);
                }
                break;

            case PARAMETER_XPN:
                // Ignore, debugging purposes only.
                break;

            case PARAMETER_DISTRIBUTED_CAK:
            case PARAMETER_KMD:
                MKA_LOG_DEBUG0("KaY/%i: Received MKPDU unhandled parameter [%i]. Ignored.", bus, param_type);
                break;

            case PARAMETER_ICV:
                // Already handled outside during mka_mkpdu_verify, skip
                break;

            default:
                MKA_LOG_ERROR("KaY/%i: Received MKPDU with unknown parameter [%i]. Ignored.", bus, param_type);
                break;
            }
        }

        if (param_type <= PARAMETER_ICV) {
            header_presence[param_type] = true;
            offset += sizeof(t_mka_param_generic) + MKA_ALIGN_TO_32BIT(param_len);
        }
    }

    // case 'secondary' peer has not become 'main' peer at this point
    if (!main_peer) {
        // does not make sense to continue processing, discard all logic past this point,
        // (DIST SAK/SAK USE). its life timer is already updated while processing basic parameter set
        continue_process = false;
    }

    // Conditions to not perform MACsec cipher suite negotiation, after all parameters are handled
    if ((!continue_process) || (MKA_PEER_LIVE != peer->state) || (MKA_CS_INVALID != participant->cipher)) {
        // No action

    } // Negotiation issue
    else if (!mka_select_macsec_usage(bus)) {
        MKA_LOG_WARNING("KaY/%i: Cannot agree with peer on a MACsec cipher suite. Forgetting peer.", bus, param_type);
        continue_process = false;
        mka_peer_cleanup(bus);

    } // Negotiation ok
    else {
        // No action
    }

    if (continue_process && (0U != dist_sak_offset)) {
        continue_process = mka_handle_distributed_sak(bus, &packet[dist_sak_offset], dist_sak_length);
    }

    if (continue_process && (0U != sak_use_offset)) {
        continue_process = mka_handle_sak_use(bus, &packet[sak_use_offset], sak_use_length);
    }

    bool const sak_use_expected = continue_process && (MKA_PEER_LIVE == peer->state) && peer->transmits_sak_use;
    bool const sak_use_absence = sak_use_expected && (!header_presence[PARAMETER_SAK_USE]);

    // Error happened
    if (!continue_process) {
        // No further action

    }
    else if (sak_use_absence) {
        MKA_LOG_WARNING("KaY/%i: Live peer did not sent SAK USE. Timers not updated.", bus);
        // No further action

    } // A live peer did not send a live peer list (doesn't see us as live)
    else if ((MKA_PEER_LIVE == initial_peer_state) && !header_presence[PARAMETER_LIVE_PEER_LIST]) {
        MKA_LOG_WARNING("KaY/%i: Live peer did not sent peer live list. Presence timers not updated.", bus);
        
    } // This was a valid MKPDU
    else {
        // It only makes sense to update
        if (MKA_PEER_LIVE == peer->state) {
            mka_timer_start(&peer->expiry, MKA_active_global_config->life_time);
        }

        mka_timer_start(&participant->mka_life, MKA_active_global_config->life_time);
        ctx->active = true;
    }

    (void)sak_use_absence;
}

bool mka_elect_key_server(t_MKA_bus bus)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    bool elected = true;
    bool self_key_server;
    int32_t mac_compare = memcmp(peer->sci.addr, ctx->actor_sci.addr, MKA_L2_ADDR_SIZE);

    if (MKA_ROLE_FORCE_KEY_SERVER == ctx->role) {
        self_key_server = true;
    }
    else if (MKA_ROLE_FORCE_KEY_CLIENT == ctx->role) {
        self_key_server = false;
    }
    else if (peer->key_server_priority > ctx->actor_priority) {
        self_key_server = true;
    }
    else if (peer->key_server_priority < ctx->actor_priority) {
        self_key_server = false;
    }
    else if (mac_compare > 0) {
        self_key_server = true;
    }
    else if (mac_compare < 0) {
        self_key_server = false;
    }
    else {
        self_key_server = false;
        elected = false;
        MKA_LOG_ERROR("KaY/%i: Role not defined, peer has same priority and mac than me, unable to choose key server. Aborting.", bus);
    }

    if (!elected) {
        // No further action, process stuck
    }
    else if (self_key_server) {
        MKA_LOG_INFO("KaY/%i: Elected self as key server.", bus);
        bool const server_changed = !MKA_sci_equal(&ctx->key_server_sci, &ctx->actor_sci);
        participant->is_key_server = true;
        //MKA_CP_SignalNewSAK(bus); // Redundant! state below shall trigger new sak to CP
        participant->sak_state = MKA_SAK_KS_DO_GENERATE_FIRST;
        ctx->key_server_priority = ctx->actor_priority;
        MKA_CP_SetElectedSelf(bus, true);
        memcpy(&ctx->key_server_sci, &ctx->actor_sci, sizeof(t_MKA_sci));
        if (server_changed) {
            MKA_CP_SignalChgdServer(bus);
        }
    }
    else {
        MKA_LOG_INFO("KaY/%i: Elected peer as key server.", bus);
        bool const server_changed = !MKA_sci_equal(&ctx->key_server_sci, &peer->sci);
        participant->is_key_server = false;
        participant->sak_state = MKA_SAK_NOT_INSTALLED;
        ctx->key_server_priority = peer->key_server_priority;
        MKA_CP_SetElectedSelf(bus, false);
        memcpy(&ctx->key_server_sci, &peer->sci, sizeof(t_MKA_sci));
        if (server_changed) {
            MKA_CP_SignalChgdServer(bus);
        }
    }

    return elected;
}

bool mka_select_macsec_usage(t_MKA_bus bus)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    bool const local_macsec = mka_macsec_supported(ctx);
    bool const remote_macsec = peer->macsec_desired;
    t_MKA_macsec_cap macsec_capable = mka_macsec_cap_min(ctx->macsec_capable, peer->macsec_capability);
    bool agreement = true;

    macsec_capable = mka_macsec_cap_min(macsec_capable, peer->compatible_capability);

    // Case I do not want MACSEC, peer does not want MACSEC
    if (!local_macsec && !remote_macsec) {
        participant->advertise_macsec_desired = false;
        participant->advertise_macsec_capability = MKA_MACSEC_NOT_IMPLEMENTED;
        participant->cipher = MKA_CS_NULL;

        if (MKA_PEER_LIVE == peer->state) {
            mka_set_mode(bus, MKA_AUTHENTICATED); // Continue without MACSEC
            ctx->linkup_report = MKA_LINK_UP_EVENT;
        }

    } // Case I do not want MACSEC, peer wants MACSEC
    else if (!local_macsec && remote_macsec) {
        // Case peer in list:
        //  LIVE: already saw us, and did not change "macsec_desired" to false --> disagreement
        //  ELSE: still can change "macsec_desired" to false --> negotiation possible

        participant->advertise_macsec_desired = false;
        participant->advertise_macsec_capability = MKA_MACSEC_NOT_IMPLEMENTED;
        participant->cipher = MKA_CS_NULL; // attempt negotiation with NULL cipher / MACsec disable

        if (MKA_PEER_LIVE == peer->remote_state) {
            // Peer is not going to work without macsec. No further negotiation possible.
        agreement = false;
        }

    } // Case I want MACSEC, peer wants MACSEC
    else if (remote_macsec) {
        participant->advertise_macsec_desired = true;
        participant->advertise_macsec_capability = macsec_capable;
        participant->cipher = peer->compatible_cipher;

        if (MKA_PEER_LIVE == peer->state) {
            mka_set_mode(bus, MKA_SECURED); // Use MACSEC
        }

    } // Case I want MACSEC, peer doesn't want MACSEC, but I'm allowed to work without MACSEC
    else if (mka_is_cipher_acceptable(bus, MKA_CS_NULL)) {
        participant->advertise_macsec_desired = false; // Turn MACSEC off and continue
        participant->advertise_macsec_capability = MKA_MACSEC_NOT_IMPLEMENTED;
        participant->cipher = MKA_CS_NULL;

        if (MKA_PEER_LIVE == peer->state) {
            mka_set_mode(bus, MKA_AUTHENTICATED); // Continue without MACSEC
            ctx->linkup_report = MKA_LINK_UP_EVENT;
        }

    } // Case I want MACSEC, peer doesn't want MACSEC, I'm not allowed to work without MACSEC
    else {
        // I am not not going to work without macsec. No further negotiation possible.
        participant->advertise_macsec_desired = true;
        participant->advertise_macsec_capability = ctx->macsec_capable;
    
        agreement = false; // no mode change, negotiation fails
    }

    switch(participant->advertise_macsec_capability) {
    case MKA_MACSEC_NOT_IMPLEMENTED:
        participant->conf_offset = MKA_CONFIDENTIALITY_NONE;
        break;
    case MKA_MACSEC_INTEGRITY:
        participant->conf_offset = MKA_CONFIDENTIALITY_NONE;
        break;
    case MKA_MACSEC_INT_CONF_0:
        participant->conf_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        break;
    case MKA_MACSEC_INT_CONF_0_30_50:
    default:
        // NOTE: it's up to the server to decide; overwritten by DIST SAK if key client
        participant->conf_offset = cfg->impl.conf_offset_preference;
        break;
    }

    return agreement;
}

void mka_peer_cleanup(t_MKA_bus bus)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_mka_peer*const peer = &participant->peer;
    t_MKA_sak* const keys[2] = { &participant->new_sak, &participant->current_sak };

    MKA_LOG_DEBUG2("KaY/%i: Cleaning up peer.", bus);
    uint8_t i;
    for(i=0U; i<2U; ++i) {
        //lint -e{644} false positive, keys is initialised right above!
        if (NULL != keys[i]->rxsa) {
            MKA_SECY_DestroyReceiveSA(bus, keys[i]->rxsa);
            keys[i]->rxsa = NULL;
        }
        if (NULL != keys[i]->txsa) {
            MKA_SECY_DestroyTransmitSA(bus, keys[i]->txsa);
            keys[i]->txsa = NULL;
        }
    }

    // Clear secure channels
    if (NULL != ctx->rxsc) {
        MKA_SECY_DestroyReceiveSC(bus, ctx->rxsc);
        ctx->rxsc = NULL;
    }

    participant->advertise_macsec_desired = false;
    participant->is_key_server = false;
    participant->sak_state = MKA_SAK_NOT_INSTALLED;
    ctx->linkup_report = MKA_LINK_DOWN;
    mka_set_mode(bus, mka_timer_expired(&participant->mka_life) ? MKA_FAILED : MKA_PENDING);

    memset(peer, 0, sizeof(t_mka_peer));
    mka_timer_stop(&peer->expiry);

    // possible scenarios (specially important when acting as key server):
    //  1) peer emits a secure announcement with its own list of preferred ciphers.
    //      -> see IEEE802.1X-2020 11.12.3 MACsec Cipher Suites TLV
    //      -> we'll consider peer's list
    //  2) no announcement
    //      -> we'll assume our preferred cipher suite is compatible and continue with it
    //

    // -> we'll set our preferred cipher suite until an announcement is handled
    peer->compatible_cipher = cfg->impl.cipher_preference[0];
    peer->compatible_capability = cfg->kay.macsec_capable;
}


void mka_participant_cleanup(t_MKA_bus bus)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;

    // Timer references
    t_mka_timer participant_cak_life = participant->cak_life;
    t_mka_timer participant_mka_life = participant->mka_life;
    t_mka_timer participant_hello    = participant->hello;

    MKA_LOG_DEBUG2("KaY/%i: Cleaning up participant.", bus);

    mka_timer_stop(&participant->mka_life);
    mka_peer_cleanup(bus);
    memset(&participant->peer_secondary, 0, sizeof(participant->peer_secondary));
    mka_timer_init(&participant->peer_secondary.expiry);

    mka_timer_init(&participant_cak_life);
    mka_timer_init(&participant_mka_life);
    mka_timer_init(&participant_hello);

    // Wipe out
    memset(participant, 0, sizeof(t_mka_participant));

    participant->cak_life = participant_cak_life ;
    participant->mka_life = participant_mka_life ;
    participant->hello    = participant_hello    ;

    // CP tasks
    MKA_CP_SetAllReceiving(bus, false);
    MKA_CP_SetServerTransmitting(bus, false);
    MKA_CP_SetUsingReceiveSAs(bus, false);
    MKA_CP_SetUsingTransmitSA(bus, false);
}

void mka_new_participant_mi(t_MKA_bus bus)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;

    MKA_LOG_DEBUG0("KaY/%i: Creating new participant MI.", bus);

    memset(participant->ks_history, 0, sizeof(participant->ks_history));

    // Clear participant's peer
    mka_peer_cleanup(bus);
    memset(&participant->peer_secondary, 0, sizeof(participant->peer_secondary));
    mka_timer_init(&participant->peer_secondary.expiry);

    MKA_ASSERT(MKA_GetRandomBytes(sizeof(participant->mi), participant->mi), "Cannot generate random numbers");

    participant->mn = 0U;

    // CP tasks
    MKA_CP_SetAllReceiving(bus, false);
    MKA_CP_SetServerTransmitting(bus, false);
    MKA_CP_SetUsingReceiveSAs(bus, false);
    MKA_CP_SetUsingTransmitSA(bus, false);
}

void mka_receive_from_l2(t_MKA_bus bus)
{
    t_mka_kay const*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_MKA_l2_ether_header const*const ethhdr = ETHHDR_FROM_CONST_PACKET(mka_frame_buffer);
    //lint -e{9087, 826} [MISRA 2012 Rule 11.3, required] Pointer cast controlled; packed struct representing network data
    t_mka_eapol_header const*const eapolhdr = EAPOL_FROM_CONST_PACKET(mka_frame_buffer);
    uint32_t ethernet_len = sizeof(mka_frame_buffer);

    if (MKA_OK == MKA_l2_receive(bus, mka_frame_buffer, &ethernet_len)) {
        uint32_t const mka_frame_len = ethernet_len - sizeof(t_MKA_l2_ether_header);
        // IEEE 802.1X 11.3 EAPOL
        uint32_t const eap_header_size = 4U;

        if (MKA_ATOMIC_FALSE == ctx->enable) {
            MKA_LOG_DEBUG3("KaY/%i: Ignoring ethernet frame: disabled bus.", bus);
        }
        else if (!participant->enable) {
            MKA_LOG_DEBUG3("KaY/%i: Ignoring ethernet frame: no actor enabled in bus.", bus);
        }
        else if (MKA_HTONS(MKA_L2_PROTO_EAPOL) != ethhdr->type) {
            MKA_LOG_DEBUG3("KaY/%i: Received ethernet frame of unhandled ethertype. Ignored.", bus);
            // No action, shouldn't happen
        }
        else if (eap_header_size >= mka_frame_len) {
            MKA_LOG_WARNING("KaY/%i: Received ethernet frame too short for EAPOL frame. Ignored.", bus);
        }
        else {
            uint16_t const body_length = MKA_NTOHS(eapolhdr->body_length);

            MKA_LOG_DEBUG3("KaY/%i: Received EAPOL message from %s version %i, type %i, length %i",
                        bus, MKA_MAC_to_string(ethhdr->src), eapolhdr->version, eapolhdr->type, body_length);

            if (eapolhdr->version != MKA_EAPOL_VERSION) {
                MKA_LOG_WARNING("KaY/%i: Received EAPOL frame with version %i, only version 3 supported!", bus, eapolhdr->version);
            }
            else if ((eap_header_size + body_length) > mka_frame_len) {
                MKA_LOG_WARNING("KaY/%i: Received truncated MKPDU (body length %i bytes). Ignored.", bus, body_length);
            }
            else if (MKA_EAPOL_TYPE_MKAPDU != eapolhdr->type) {
                MKA_LOG_DEBUG1("KaY/%i: Received non-MKA PDU. Ignored.", bus);
            }
            else if (!mka_mkpdu_verify(bus, mka_frame_buffer, &ethernet_len)) {
                // Ignore
            }
            else {
                mka_handle_mkpdu(bus, mka_frame_buffer, ethernet_len);
            }
        }
    }
}

bool mka_sak_nonce_protection(t_MKA_bus bus, uint8_t const* mi, uint32_t kn, t_MKA_pn next_pn)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_sak_nonce_pair* empty_slot = NULL;
    t_sak_nonce_pair* server_slot = NULL;
    bool triggered = false;
    uint8_t i;

    for(i=0U; i<MKA_ARRAY_SIZE(participant->ks_history); ++i) {
        t_sak_nonce_pair*const pair = &participant->ks_history[i];

        // Empty slot
        if (0U == pair->next_pn) {
            empty_slot = (NULL == empty_slot) ? pair : empty_slot;

        } // MI does not match, different key server
        else if (!MKA_mi_equal(pair->ki.mi, mi)) {
            // Nothing
        }
        else {
            server_slot = pair;
        }
    }

    // SAK-nonce pair previously distributed
    if ((NULL != server_slot) && (server_slot->ki.kn == kn) && (server_slot->next_pn == next_pn)) {
        MKA_LOG_ERROR("KaY/%i: SAK-nonce pair protection triggered!! SAK rejected. Restarting participant with new MI.", bus);
        mka_new_participant_mi(bus);
        triggered = true;

    }
    else if (NULL != server_slot) {
        MKA_LOG_DEBUG3("KaY/%i: Updating nonce-pair entry for received SAK.", bus);
        server_slot->next_pn = next_pn;
        memcpy(server_slot->ki.mi, mi, MKA_MI_LENGTH);
        server_slot->ki.kn = kn;
        triggered = false;

    }
    else if (NULL == empty_slot) {
        MKA_LOG_WARNING("KaY/%i: No slot to record SAK-nonce pair. Restarting participant with new MI to free slots.", bus);
        mka_new_participant_mi(bus);
        triggered = true;

    }
    else {
        MKA_LOG_DEBUG3("KaY/%i: Registering new SAK-nonce pair for received SAK.", bus);
        empty_slot->next_pn = next_pn;
        memcpy(empty_slot->ki.mi, mi, MKA_MI_LENGTH);
        empty_slot->ki.kn = kn;
        triggered = false;
    }

    return triggered;
}

t_MKA_sak* mka_find_key(t_MKA_bus bus, uint8_t const* mi, uint32_t kn)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_MKA_sak* sak;

    // Case call from CP with empty key, prevent referencing internal kay structures
    if (MKA_is_mi_null(mi) && (0U == kn)) {
        sak = NULL;
    }
    else if (MKA_mi_equal(participant->new_sak.identifier.mi, mi) &&
            (participant->new_sak.identifier.kn == kn)) {
        sak = &participant->new_sak;
    }
    else if (MKA_mi_equal(participant->current_sak.identifier.mi, mi) &&
            (participant->current_sak.identifier.kn == kn)) {
        sak = &participant->current_sak;
    }
    else {
        sak = NULL;
    }

    return sak;
}

void MKA_KAY_CreateSAs(t_MKA_bus bus, t_MKA_ki const* ki)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant const*const participant = &ctx->participant;
    t_mka_peer const*const peer = &participant->peer;
    t_MKA_sak* key = mka_find_key(bus, ki->mi, ki->kn);
    t_MKA_ssci own_ssci = (peer->ssci == SSCI_FIRST) ? (uint32_t)SSCI_SECOND : (uint32_t)SSCI_FIRST;

    // Get key reference
    if (NULL == key) {
        ctx->secy_error_occurred = true;
        MKA_LOG_ERROR("KaY/%i Cannot find SAK associated with KI while creating a Secure Association", bus);
    }

    // Create Transmission Secure Channel if not present
    if ((NULL == ctx->txsc) && (key != NULL)) {
        ctx->secy_error_occurred = true;
        MKA_LOG_ERROR("KaY/%i Transmission secure channel is NULL, cannot create SA", bus);
    }

    // Create Transmission Secure Association
    if ((NULL != ctx->txsc) && (key != NULL)) {
        key->txsa = MKA_SECY_CreateTransmitSA(
                    /* bus ID (impl. spec.) */  bus,
                    /* association number   */  key->association_number,
                    /* nextPN               */  1ULL,
                    /* SSCI                 */  own_ssci,
                    /* confidentiality      */  key->confidentiality_offset,
                    /* SAK                  */  key->secy_reference
                );
        if (NULL == key->txsa) {
            ctx->secy_error_occurred = true;
            MKA_LOG_ERROR("KaY/%i SecY returned NULL Secure Association", bus);
        }
    }

    // Create Reception Secure Channel if not present
    if ((NULL == ctx->rxsc) && (key != NULL)) {
        ctx->rxsc = MKA_SECY_CreateReceiveSC(bus, &peer->sci);
        if (NULL == ctx->rxsc) {
            ctx->secy_error_occurred = true;
            MKA_LOG_ERROR("KaY/%i SecY returned NULL Receive Secure Channel", bus);
        }
    }

    // Create Reception Secure Association
    if ((NULL != ctx->rxsc) && (key != NULL)) {
        key->rxsa = MKA_SECY_CreateReceiveSA(
                    /* bus ID (impl. spec.) */  bus,
                    /* association number   */  key->association_number,
                    /* lowestPN             */  1ULL,
                    /* SSCI                 */  peer->ssci,
                    /* SAK                  */  key->secy_reference
                );
        if (NULL == key->rxsa) {
            ctx->secy_error_occurred = true;
            MKA_LOG_ERROR("KaY/%i SecY returned NULL Secure Association", bus);
        }
    }
}

void MKA_KAY_DeleteSAs(t_MKA_bus bus, t_MKA_ki const* ki)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_MKA_sak* key = mka_find_key(bus, ki->mi, ki->kn);

    if ((NULL != key) && (NULL != key->rxsa)) {
        MKA_SECY_DestroyReceiveSA(bus, key->rxsa);
        key->rxsa = NULL;
    }

    if ((NULL != key) && (NULL != key->txsa)) {
        MKA_SECY_DestroyTransmitSA(bus, key->txsa);
        key->txsa = NULL;
    }

    // CP is erasing SA associated to current SAK, we just completed a key rotation
    if (key == &participant->current_sak) {
        memcpy(&participant->current_sak, &participant->new_sak, sizeof(t_MKA_sak));
        memset(&participant->new_sak, 0, sizeof(t_MKA_sak));
    }
}

void MKA_KAY_EnableReceiveSAs(t_MKA_bus bus, t_MKA_ki const* ki)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_MKA_sak *const key = mka_find_key(bus, ki->mi, ki->kn);

    // Must be unconditional to avoid CP FSM getting stuck!
    MKA_CP_SetUsingReceiveSAs(bus, true);

    if (NULL == key) {
        MKA_LOG_ERROR("KaY/%i CP requesting to activate a non-installed KI", bus);
    }
    else if (MKA_OK == MKA_SECY_ReceiveSA_EnableReceive(bus, key->rxsa)) {
        key->receives = true;
    } // Error related with secy
    else {
        ctx->secy_error_occurred = true;
    }
}

void MKA_KAY_EnableTransmitSA(t_MKA_bus bus, t_MKA_ki const* ki)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_MKA_sak *const key = mka_find_key(bus, ki->mi, ki->kn);

    // Must be unconditional to avoid CP FSM getting stuck!
    MKA_CP_SetUsingTransmitSA(bus, true);

    // Get key reference
    if (NULL == key) {
        MKA_LOG_ERROR("KaY/%i CP requesting to activate a non-installed KI", bus);
    }
    else if (MKA_OK == MKA_SECY_TransmitSA_EnableTransmit(bus, key->txsa)) {
        participant->current_sak.transmits = false;
        participant->new_sak.transmits = false;
        key->transmits = true;

        if (MKA_LINK_DOWN == ctx->linkup_report) {
            ctx->linkup_report = MKA_LINK_UP_REPORTING;
        }
    } // Error related with secy
    else {
        ctx->secy_error_occurred = true;
    }
}

void mka_set_mode(t_MKA_bus bus, t_MKA_connect_mode mode)
{
    t_mka_kay*const ctx = &mka_kay[bus];

    if (ctx->mode != mode) {
        MKA_LOGON_SetKayConnectMode(bus, mode);
        ctx->mode = mode;
    }
}

bool mka_create_new_sak(t_MKA_bus bus)
{
    t_mka_kay*const ctx = &mka_kay[bus];
    t_mka_participant*const participant = &ctx->participant;
    t_MKA_key sak_holder;
    t_MKA_sak* const sak = &participant->new_sak;
    uint32_t kn = participant->current_sak.identifier.kn + 1U;
    uint8_t an = (participant->current_sak.association_number + 1U) & 3U;
    uint32_t key_size;
    bool result;

    if (    (MKA_CS_ID_GCM_AES_XPN_256 == participant->cipher) ||
            (MKA_CS_ID_GCM_AES_256 == participant->cipher)) {
        key_size = MKA_KEY_256BIT;
    }
    else {
        key_size = MKA_KEY_128BIT;
    }

#if !defined(MKA_GENERATE_RANDOM_SAK) || (MKA_GENERATE_RANDOM_SAK == MKA_OFF)
    uint8_t randomness[MKA_KEY_256BIT];
#endif

    // No MACSEC
    if (MKA_CS_NULL == participant->cipher) {
        result = true; // No action!
    }
#if !defined(MKA_GENERATE_RANDOM_SAK) || (MKA_GENERATE_RANDOM_SAK == MKA_OFF)
    else if (!MKA_GetRandomBytes(key_size, randomness)) {
        MKA_LOG_ERROR("KaY/%i: Cannot create ks_nonce of size %i for SAK derivation.", bus, key_size);
        result = false;
    }
    else if (!MKA_DeriveSAK(
            /* cak key  */  &participant->cak,
            /* ks_nonce */  randomness,
            /* mi_local */  participant->mi,
            /* mi_peer  */  participant->peer.mi,
            /* kn       */  kn,
            /* out_len  */  key_size,
            /* sak      */  &sak_holder
            )) {
        MKA_LOG_ERROR("KaY/%i: Cannot derive SAK key from CAK.", bus, key_size);
        result = false;
    }
#else // MKA_GENERATE_RANDOM_SAK
    else if (!MKA_CreateRandomKey(key_size, &sak_holder)) {
        MKA_LOG_ERROR("KaY/%i: Cannot create randomly generated SAK key of size %i.", bus, key_size);
    }
#endif
    else {
        //sak->secy_reference = NULL;
        sak->next_pn = 1ULL;
        sak->confidentiality_offset = participant->conf_offset;
        sak->association_number = an;
        sak->cipher = participant->cipher;
        sak->creation = mka_tick_time_ms;
        sak->transmits = false;
        sak->receives = false;

        sak->identifier.kn = kn;
        memcpy(sak->identifier.mi, participant->mi, MKA_MI_LENGTH);

        sak->secy_reference = MKA_SECY_InstallKey(bus, &sak_holder, &sak->identifier, true, true);
        sak->txsa = NULL;
        sak->rxsa = NULL;

        result = MKA_WrapKey(&participant->kek, &sak_holder, participant->new_sak_wrapped);
        memset(&sak_holder, 0, sizeof(sak_holder));
    }

    return result;
}

t_MKA_result MKA_KAY_GetBusInfo(t_MKA_bus bus, t_MKA_bus_info* info)
{
    const t_mka_kay *const ctx = &mka_kay[bus];
    const t_MKA_bus_info *const bus_info = &ctx->state_info;

    MKA_CRITICAL_ENTER();
    (void)memcpy(info, bus_info, sizeof(*info));
    MKA_CRITICAL_LEAVE();

    return MKA_OK;
}


/** @} */

