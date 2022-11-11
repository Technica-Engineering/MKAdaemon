/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_cp.c
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
 * @file        mka_cp.c
 * @version     1.0.0
 * @author      Ferran Pedrera
 * @brief       PAE Controller Port (CP) implementation (802.1x 2020 Chapter 12)
 *
 * @{
 */

/*******************        Includes        *************************/

#include "mka_cp.h"
#include "mka_kay.h"
#include "mka_secy.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*! @brief Enum for CP connect interface */
typedef enum {
    CONNECT_PENDING,
    CONNECT_UNAUTHENTICATED,
    CONNECT_AUTHENTICATED,
    CONNECT_SECURE
} t_connect_type;

/*! @brief Enum for CP FSM states*/
typedef enum {
    STATE_CP_INIT,
    STATE_CP_CHANGE,
    STATE_CP_ALLOWED,
    STATE_CP_AUTHENTICATED,
    STATE_CP_SECURED,
    STATE_CP_RECEIVE,
    STATE_CP_RECEIVING,
    STATE_CP_READY,
    STATE_CP_TRANSMIT,
    STATE_CP_TRANSMITTING,
    STATE_CP_ABANDON,
    STATE_CP_RETIRE
} t_fsm_state_MKA_CP;

/*! @brief Struct storing all CP FSM data */
typedef struct {
    FSM_DECLARE_MEMBER(MKA_CP);

    /* CP -> Client */
    bool port_valid;

    /* Logon -> CP */
    t_connect_type connect;

    /* KaY -> CP */
    bool chgd_server; /* clear by CP */
    bool elected_self;
    uint64_t cipher_suite;
    t_MKA_confidentiality_offset cipher_offset;
    bool new_sak; /* clear by CP */
    t_MKA_ki distributed_ki;
    uint8_t distributed_an;
    bool using_receive_sas;
    bool all_receiving;
    bool server_transmitting;
    bool using_transmit_sa;

    /* CP -> KaY */
    t_MKA_ki lki;
    uint8_t lan;
    bool ltx;
    bool lrx;
    t_MKA_ki oki;
    uint8_t oan;
    bool otx;
    bool orx;

    /* CP -> SecY */
    t_MKA_SECY_config secy_config;

    /* SecY -> CP */
    bool port_enabled; /* SecY->CP */

    /* private */
    uint32_t transmit_when;
    uint32_t transmit_delay;
    t_mka_timer transmit_timer;
    uint32_t retire_when;
    uint32_t retire_delay;
    t_mka_timer retire_timer;
} t_fsm_MKA_CP;

/*******************        Variables         ***********************/

/*! @brief Array storing data for CP FSM instances */
static t_fsm_MKA_CP fsm_MKA_CP[MKA_NUM_BUSES];

/*******************        Func. prototypes  ***********************/

/**
 * Function to update all CP output interfaces.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
static void MKA_CP_UpdateInterfaces(t_MKA_bus bus);

/**
 * Function to check if either current cipher suite or cipher offset is
 * different from the ones requested.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * 
 * @return true: cipher parameters have been modified
 * @return false: cipher parameters remain the same
 */
static bool MKA_CP_ChangedCipher(t_MKA_bus bus);

/**
 * Function to check if connect, chgdServer or cipher parameters have been modified.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * 
 * @return true: parameters have been modified
 * @return false: parameters remain the same
 */
static bool MKA_CP_ChangedConnect(t_MKA_bus bus);

/* Declare FSM related functions */
FSM_DECLARE_ACTIVITY_FUNC(MKA_CP);
FSM_DECLARE_INITIAL_STATE(MKA_CP, STATE_CP_INIT);
/*lint -estring(621, fsm_entry_func_*) State functions autodeclared by MKA FSM library */
FSM_DECLARE_STATE(MKA_CP, STATE_CP_CHANGE);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_ALLOWED);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_AUTHENTICATED);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_SECURED);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_RECEIVE);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_RECEIVING);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_READY);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_TRANSMIT);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_TRANSMITTING);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_ABANDON);
FSM_DECLARE_STATE(MKA_CP, STATE_CP_RETIRE);

/*******************        Func. definition  ***********************/

/************** FSM functions **************/

static void MKA_CP_UpdateInterfaces(t_MKA_bus bus)
{
    /* Update interfaces CP -> SecY*/
    (void)MKA_SECY_UpdateConfiguration(bus, &fsm_MKA_CP[bus].secy_config);
}

static bool MKA_CP_ChangedCipher(t_MKA_bus bus)
{
    return (fsm_MKA_CP[bus].secy_config.confidentiality_offset != fsm_MKA_CP[bus].cipher_offset) || 
           (fsm_MKA_CP[bus].secy_config.current_cipher_suite != fsm_MKA_CP[bus].cipher_suite);
}

static bool MKA_CP_ChangedConnect(t_MKA_bus bus)
{
    return (fsm_MKA_CP[bus].connect != CONNECT_SECURE) || 
            fsm_MKA_CP[bus].chgd_server || 
            MKA_CP_ChangedCipher(bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_INIT)
{
    fsm->secy_config.controlled_port_enabled = false;
    fsm->port_valid = false;
    fsm->chgd_server = false;

    /* Get macsec config from KaY */
    fsm->secy_config.protect_frames  = MKA_KAY_GetProtectFrames(fsm->bus);
    fsm->secy_config.validate_frames = MKA_KAY_GetValidateFrames(fsm->bus);
    fsm->secy_config.replay_protect  = MKA_KAY_GetReplayProtect(fsm->bus);
    fsm->secy_config.replay_window   = MKA_KAY_GetReplayWindow(fsm->bus);

    /* Clear SAs info*/
    os_memset(&fsm->lki,0,sizeof(t_MKA_ki));
    fsm->lan = 0;
    fsm->lrx = false;
    fsm->ltx = false;
    os_memset(&fsm->oki,0,sizeof(t_MKA_ki));
    fsm->oan = 0;
    fsm->orx = false;
    fsm->otx = false;

    /* Set event to signal portValid change  */
    MKA_BUS_EVENT(fsm->bus, MKA_EVENT_PORT_NOT_VALID);
    
    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_CHANGE)
{
    fsm->port_valid = false;
    fsm->secy_config.controlled_port_enabled = false;

    /* Delete SAs */
    MKA_KAY_DeleteSAs(fsm->bus, &fsm->lki);
    MKA_KAY_DeleteSAs(fsm->bus, &fsm->oki);

    /* Clear SAs info*/
    os_memset(&fsm->lki,0,sizeof(t_MKA_ki));
    fsm->lan = 0;
    fsm->lrx = false;
    fsm->ltx = false;
    os_memset(&fsm->oki,0,sizeof(t_MKA_ki));
    fsm->oan = 0;
    fsm->orx = false;
    fsm->otx = false;

    /* Set event to signal portValid change  */
    MKA_BUS_EVENT(fsm->bus, MKA_EVENT_PORT_NOT_VALID);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_ALLOWED)
{
    fsm->secy_config.protect_frames = false;
    fsm->secy_config.replay_protect = false;
    fsm->secy_config.validate_frames = MKA_VALIDATE_CHECKED;
    fsm->secy_config.controlled_port_enabled = true;
    fsm->port_valid = false;

    /* Set event to signal portValid change  */
    MKA_BUS_EVENT(fsm->bus, MKA_EVENT_PORT_NOT_VALID);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_AUTHENTICATED)
{
    fsm->secy_config.protect_frames = false;
    fsm->secy_config.replay_protect = false;
    fsm->secy_config.validate_frames = MKA_VALIDATE_CHECKED;
    fsm->secy_config.controlled_port_enabled = true;
    fsm->port_valid = false;

    /* Set event to signal portValid change  */
    MKA_BUS_EVENT(fsm->bus, MKA_EVENT_PORT_NOT_VALID);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_SECURED)
{
    fsm->chgd_server = false;
    fsm->secy_config.current_cipher_suite = fsm->cipher_suite;
    fsm->secy_config.confidentiality_offset = fsm->cipher_offset;
    fsm->port_valid = true;

    /* Get macsec config from KaY */
    fsm->secy_config.protect_frames  = MKA_KAY_GetProtectFrames(fsm->bus);
    fsm->secy_config.replay_protect  = MKA_KAY_GetReplayProtect(fsm->bus);
    fsm->secy_config.replay_window   = MKA_KAY_GetReplayWindow(fsm->bus);
    fsm->secy_config.validate_frames = MKA_KAY_GetValidateFrames(fsm->bus);

    /* Set event to signal portValid change  */
    MKA_BUS_EVENT(fsm->bus, MKA_EVENT_PORT_VALID);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_RECEIVE)
{
    /* Copy distributed KI & AN into lki, lan */
    os_memcpy(&fsm->lki, &fsm->distributed_ki, sizeof(t_MKA_ki));
    fsm->lan = fsm->distributed_an;
    fsm->ltx = false;
    fsm->lrx = false;

    /* Request Latest SA creation & reception to KaY */
    MKA_KAY_CreateSAs(fsm->bus, &fsm->lki);
    MKA_KAY_EnableReceiveSAs(fsm->bus, &fsm->lki);

    /* Clear newSAK signal */
    fsm->new_sak = false;

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_RECEIVING)
{
    fsm->lrx = true;
    fsm->transmit_when = fsm->transmit_delay;

    /* Init transmitWhen timer */
    mka_timer_start(&fsm->transmit_timer, fsm->transmit_when);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_READY)
{
    /* Signal newInfo to KaY */
    MKA_KAY_SignalNewInfo(fsm->bus);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_TRANSMIT)
{
    fsm->secy_config.controlled_port_enabled = true;
    fsm->ltx = true;

    /* Request Latest SA transmission to KaY */
    MKA_KAY_EnableTransmitSA(fsm->bus, &fsm->lki);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_TRANSMITTING)
{
    fsm->retire_when = fsm->orx ? fsm->retire_delay : 0U;
    fsm->otx = false;

    /* Signal newInfo to KaY */
    MKA_KAY_SignalNewInfo(fsm->bus);

    /* Init retireWhen timer */
    mka_timer_start(&fsm->retire_timer, fsm->retire_when);

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_ABANDON)
{
    /* Request SA deletion to KaY */
    MKA_KAY_DeleteSAs(fsm->bus, &fsm->lki);

    /* Clear Latest SA */
    os_memset(&fsm->lki,0,sizeof(t_MKA_ki));
    fsm->lan = 0;
    fsm->lrx = false;
    fsm->ltx = false;

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}


FSM_IMPLEMENT_ENTRY_FUNC(MKA_CP, STATE_CP_RETIRE)
{
    MKA_KAY_DeleteSAs(fsm->bus, &fsm->oki);

    /* Copy Latest SA into Old SA */
    os_memcpy(&fsm->oki, &fsm->lki, sizeof(t_MKA_ki));
    fsm->otx = fsm->ltx;
    fsm->orx = fsm->lrx;
    fsm->oan = fsm->lan;

    /* Clear Latest SA */
    os_memset(&fsm->lki,0,sizeof(t_MKA_ki));
    fsm->lan = 0;
    fsm->lrx = false;
    fsm->ltx = false;

    /* Update interfaces */
    MKA_CP_UpdateInterfaces(fsm->bus);
}

/* 802.1x 2020 Figure 12-2 */
FSM_IMPLEMENT_ACTIVITY_FUNC(MKA_CP)
{
    if (!fsm->port_enabled) {
        if(fsm->state != STATE_CP_INIT) {
            FSM_TRANSITION(MKA_CP, STATE_CP_INIT);
        }
    }
    else {
        switch(fsm->state) {
            case STATE_CP_INIT:
                FSM_TRANSITION(MKA_CP, STATE_CP_CHANGE);
                break;
            case STATE_CP_CHANGE:
                /* Check transitions conditions */
                if(fsm->connect == CONNECT_UNAUTHENTICATED) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_ALLOWED);
                }
                else if(fsm->connect == CONNECT_AUTHENTICATED) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_AUTHENTICATED);
                }
                else if(fsm->connect == CONNECT_SECURE) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_SECURED);
                }
                else {
                    /* Do nothing */
                }
                break;
            case STATE_CP_ALLOWED:
                /* Check transitions conditions */
                if(fsm->connect != CONNECT_UNAUTHENTICATED) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_CHANGE);
                }
                break;
            case STATE_CP_AUTHENTICATED:
                /* Check transitions conditions */
                if(fsm->connect != CONNECT_AUTHENTICATED) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_CHANGE);
                }
                break;
            case STATE_CP_SECURED:
                /* Check transitions conditions */
                if(MKA_CP_ChangedConnect(fsm->bus)) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_CHANGE);
                }
                else if(fsm->new_sak) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_RECEIVE);
                }
                else {
                    /* Do nothing */
                }
                break;
            case STATE_CP_RECEIVE:
                /* Check transitions conditions */
                if (fsm->using_receive_sas) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_RECEIVING);
                }
                break;
            case STATE_CP_RECEIVING:
                /* Check transmit timer expiration */
                if(mka_timer_expired(&fsm->transmit_timer)) {
                    fsm->transmit_when = 0U;
                }
                /* Check transitions conditions */
                if (fsm->new_sak || MKA_CP_ChangedConnect(fsm->bus)) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_ABANDON);
                }
                else if (!fsm->elected_self) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_READY);
                }
                else if ( fsm->elected_self &&
                    (fsm->all_receiving || (false == fsm->secy_config.controlled_port_enabled) || (0U == fsm->transmit_when))) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_TRANSMIT);
                }
                else {
                    /* Do nothing */
                }
                break;
            case STATE_CP_TRANSMIT:
                /* Check transitions conditions */
                if(fsm->using_transmit_sa) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_TRANSMITTING);
                }
                break;
            case STATE_CP_TRANSMITTING:
                /* Check retire timer expiration */
                if(mka_timer_expired(&fsm->retire_timer)) {
                    fsm->retire_when = 0U;
                }
                /* Check transitions conditions */
                if( (0U == fsm->retire_when) || MKA_CP_ChangedConnect(fsm->bus)) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_RETIRE);
                }
                break;
            case STATE_CP_RETIRE:
                if(MKA_CP_ChangedConnect(fsm->bus)) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_CHANGE);
                }
                else if(fsm->new_sak) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_RECEIVE);
                }
                else {
                    /* Do nothing */
                }
                break;
            case STATE_CP_READY:
                if(fsm->new_sak || MKA_CP_ChangedConnect(fsm->bus)) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_ABANDON);
                }
                else if(fsm->server_transmitting || !fsm->secy_config.controlled_port_enabled) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_TRANSMIT);
                }
                else {
                    /* Do nothing */
                }
                break;
            case STATE_CP_ABANDON:
                if(MKA_CP_ChangedConnect(fsm->bus)) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_RETIRE);
                }
                else if(fsm->new_sak) {
                    FSM_TRANSITION(MKA_CP, STATE_CP_RECEIVE);
                }
                else {
                    /* Do nothing */
                }
                break;
            default:
                MKA_LOG_WARNING("State not defined in FSM");
                break;
        }
    }
}

/************** Public APIs **************/

void MKA_CP_Init(t_MKA_bus bus)
{
    /* Zero init instance data */
    (void)memset(&fsm_MKA_CP[bus],0,sizeof(t_fsm_MKA_CP));

    /* Set default data different from zero */
    fsm_MKA_CP[bus].secy_config.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    fsm_MKA_CP[bus].secy_config.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    fsm_MKA_CP[bus].cipher_suite = MKA_CS_ID_GCM_AES_128;
    fsm_MKA_CP[bus].cipher_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    fsm_MKA_CP[bus].transmit_delay = MKA_active_global_config->life_time;
    fsm_MKA_CP[bus].retire_delay = MKA_active_global_config->sak_retire_time;

    FSM_INIT(MKA_CP, &fsm_MKA_CP[bus], bus);
}

void MKA_CP_MainFunction(t_MKA_bus bus)
{
    FSM_RUN_UNTIL_STABLE(MKA_CP, &fsm_MKA_CP[bus]);
}

#ifdef UNIT_TEST // Unit test only: single tick of the state machine
void MKA_CP_MainFunctionTick(t_MKA_bus bus);
void MKA_CP_MainFunctionTick(t_MKA_bus bus)
{
    FSM_RUN(MKA_CP, &fsm_MKA_CP[bus]);
}
#endif

void MKA_CP_SetPortEnabled(t_MKA_bus bus, bool status)
{
    fsm_MKA_CP[bus].port_enabled = status;
}

void MKA_CP_SetCipherSuite(t_MKA_bus bus, uint64_t cipher_suite)
{
    fsm_MKA_CP[bus].cipher_suite = cipher_suite;
}

void MKA_CP_SetCipherOffset(t_MKA_bus bus, t_MKA_confidentiality_offset cipher_offset)
{
    fsm_MKA_CP[bus].cipher_offset = cipher_offset;
}

void MKA_CP_SetDistributedKI(t_MKA_bus bus, const t_MKA_ki * ki)
{
    os_memcpy(&fsm_MKA_CP[bus].distributed_ki, ki, sizeof(t_MKA_ki));
}

void MKA_CP_SetDistributedAN(t_MKA_bus bus, uint8_t an)
{
    fsm_MKA_CP[bus].distributed_an = an;
}

void MKA_CP_SetUsingReceiveSAs(t_MKA_bus bus, bool status)
{
    fsm_MKA_CP[bus].using_receive_sas = status;
}

void MKA_CP_SetElectedSelf(t_MKA_bus bus, bool status)
{
    fsm_MKA_CP[bus].elected_self = status;
}

void MKA_CP_SetAllReceiving(t_MKA_bus bus, bool status)
{
    fsm_MKA_CP[bus].all_receiving = status;
}

void MKA_CP_SetUsingTransmitSA(t_MKA_bus bus, bool status)
{
    fsm_MKA_CP[bus].using_transmit_sa = status;
}

void MKA_CP_SetServerTransmitting(t_MKA_bus bus, bool status)
{
    fsm_MKA_CP[bus].server_transmitting = status;
}

void MKA_CP_SignalChgdServer(t_MKA_bus bus)
{
    fsm_MKA_CP[bus].chgd_server = true;
}

void MKA_CP_SignalNewSAK(t_MKA_bus bus)
{
    fsm_MKA_CP[bus].new_sak = true;
}

void MKA_CP_ConnectPending(t_MKA_bus bus)
{
    fsm_MKA_CP[bus].connect = CONNECT_PENDING;
}

void MKA_CP_ConnectUnauthenticated(t_MKA_bus bus)
{
    fsm_MKA_CP[bus].connect = CONNECT_UNAUTHENTICATED;
}

void MKA_CP_ConnectAuthenticated(t_MKA_bus bus)
{
    fsm_MKA_CP[bus].connect = CONNECT_AUTHENTICATED;
}

void MKA_CP_ConnectSecure(t_MKA_bus bus)
{
    fsm_MKA_CP[bus].connect = CONNECT_SECURE;
}

bool MKA_CP_GetProtectFrames(t_MKA_bus bus)
{
    return fsm_MKA_CP[bus].secy_config.protect_frames;
}

t_MKA_validate_frames MKA_CP_GetValidateFrames(t_MKA_bus bus)
{
    return fsm_MKA_CP[bus].secy_config.validate_frames;
}

void MKA_CP_GetOldSA(t_MKA_bus bus, t_MKA_ki const**oki, uint8_t *oan, bool *otx, bool *orx)
{
    *oki = &fsm_MKA_CP[bus].oki;
    *oan =  fsm_MKA_CP[bus].oan;
    *otx =  fsm_MKA_CP[bus].otx;
    *orx =  fsm_MKA_CP[bus].orx;
}

void MKA_CP_GetLatestSA(t_MKA_bus bus, t_MKA_ki const**lki, uint8_t *lan, bool *ltx, bool *lrx)
{
    *lki = &fsm_MKA_CP[bus].lki;
    *lan =  fsm_MKA_CP[bus].lan;
    *ltx =  fsm_MKA_CP[bus].ltx;
    *lrx =  fsm_MKA_CP[bus].lrx;
}
