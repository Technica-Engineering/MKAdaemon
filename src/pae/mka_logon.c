/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_logon.c
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
 * @file        mka_logon.c
 * @version     1.0.0
 * @author      Ferran Pedrera
 * @brief       PAE Logon implementation (802.1x 2020)
 *
 * @{
 */

/*******************        Includes        *************************/

#include "mka_logon.h"
#include "mka_kay.h"
#include "mka_cp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*! @brief Struct storing LOGON data */
typedef struct {
    bool logon;
    bool port_enabled;
    bool mka_enabled;
    bool mka_created;
    t_MKA_activate activate;
} t_MKA_logon;

/*******************        Variables         ***********************/

/*! @brief Array storing data for LOGON instances */
static t_MKA_logon mka_logon[MKA_NUM_BUSES];

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/

void MKA_LOGON_Init(t_MKA_bus bus)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_MKA_logon * const ctx = &mka_logon[bus];

    ctx->port_enabled = false;
    ctx->mka_enabled = false;
    ctx->mka_created = false;
    ctx->activate = cfg->kay.pcpt_activation;
    ctx->logon = cfg->logon_process.logon;
}

void MKA_LOGON_MainFunction(t_MKA_bus bus)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_MKA_key cak, kek, ick;
    t_MKA_ckn ckn;
    uint32_t life = MKA_TIMER_MAX;

    t_MKA_logon * const ctx = &mka_logon[bus];

    if(ctx->logon && ctx->port_enabled) {
        if(ctx->mka_enabled) {
            /* If MKA is not created, retrieve KEYs and request KaY to create MKA */
            if(false == ctx->mka_created) {
                if(MKA_OK != cfg->impl.key_mng.RetrieveCAKCKN(bus, &cak, &ckn)) {
                    MKA_LOG_ERROR("Cannot retrieve CAK/CKN for bus: %d", bus);
                }
                else if(MKA_OK != cfg->impl.key_mng.RetrieveKEK(bus, &kek)) {
                    MKA_LOG_ERROR("Cannot retrieve KEK for bus: %d", bus);
                }
                else if(MKA_OK != cfg->impl.key_mng.RetrieveICK(bus, &ick)) {
                    MKA_LOG_ERROR("Cannot retrieve ICK for bus: %d", bus);
                }
                else if(true != MKA_KAY_CreateMKA(bus, &ckn, &cak, &kek, &ick, NULL, life)) {
                    MKA_LOG_ERROR("Cannot create MKA for bus: %d", bus);
                }
                else {
                    ctx->mka_created = true;
                    /* Set KaY participate according to activate configuration*/
                    MKA_KAY_Participate(bus, ((ctx->activate == MKA_ACTIVATE_ONOPERUP) || (ctx->activate == MKA_ACTIVATE_ALWAYS)) ? true:false);
                }

                /* In case error retrieving/creating KAY with PSK,
                set connect unauthenticated according to configuration */
                if(!ctx->mka_created && (cfg->logon_nid.unauth_allowed != MKA_UNAUTH_NEVER)) {
                    MKA_CP_ConnectUnauthenticated(bus);
                }
            }
        }
        else {
            if(cfg->logon_nid.unauth_allowed != MKA_UNAUTH_NEVER) {
                MKA_CP_ConnectUnauthenticated(bus);
            }
            else {
                MKA_CP_ConnectPending(bus);
            }
        }
    }
    else if(ctx->logon && (!ctx->port_enabled) && ctx->mka_enabled && ctx->mka_created) {
        /* If portEnable changes from enabled to disabled, MKA is to be deleted */
        MKA_KAY_DeleteMKA(bus);
    }
    else {
        /* Do nothing */
    }
}

void MKA_LOGON_SetLogonEnabled(t_MKA_bus bus, bool status) 
{
    t_MKA_logon * const ctx = &mka_logon[bus];

    /* Check change to print info */
    if(ctx->logon) {
        if(!status) {
            MKA_LOG_INFO("Logon instance[%d] DISABLED", bus);
        }
    }
    else {
        if(status) {
            MKA_LOG_INFO("Logon instance[%d] ENABLED", bus);
        }
    }

    ctx->logon = status;
}

void MKA_LOGON_SetKayEnabled(t_MKA_bus bus, bool status) 
{
    t_MKA_logon * const ctx = &mka_logon[bus];

    ctx->mka_enabled = status;
}

void MKA_LOGON_SignalDeletedMKA(t_MKA_bus bus) 
{
    t_MKA_logon * const ctx = &mka_logon[bus];

    ctx->mka_created = false;
}

void MKA_LOGON_SetKayConnectMode(t_MKA_bus bus, t_MKA_connect_mode mode) 
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    const t_MKA_logon * const ctx = &mka_logon[bus];

    if(ctx->logon && ctx->mka_enabled) {
        switch(mode) {
            case MKA_PENDING:
                /* Move CP according to configuration */
                if(cfg->logon_nid.unsecure_allowed == MKA_UNSECURE_IMMEDIATE) {
                    MKA_CP_ConnectAuthenticated(bus);
                }
                else if(cfg->logon_nid.unauth_allowed != MKA_UNAUTH_NEVER) {
                    MKA_CP_ConnectUnauthenticated(bus);
                }
                else {
                    MKA_CP_ConnectPending(bus);
                }
                break;
            case MKA_AUTHENTICATED:
                if(cfg->logon_nid.unsecure_allowed != MKA_UNSECURE_NEVER) {
                    MKA_CP_ConnectAuthenticated(bus);
                }
                break;
            case MKA_SECURED:
                MKA_CP_ConnectSecure(bus);
                break;
            case MKA_FAILED:
                if(ctx->activate == MKA_ACTIVATE_ONOPERUP) {
                    MKA_KAY_Participate(bus, false);
                }
                /* Move CP according to configuration */
                if( (cfg->logon_nid.unsecure_allowed == MKA_UNSECURE_IMMEDIATE) ||
                    (cfg->logon_nid.unsecure_allowed == MKA_UNSECURE_ON_MKA_FAIL)) {
                    MKA_CP_ConnectAuthenticated(bus);
                }
                else if(cfg->logon_nid.unauth_allowed != MKA_UNAUTH_NEVER) {
                    MKA_CP_ConnectUnauthenticated(bus);
                }
                else {
                    MKA_CP_ConnectPending(bus);
                }
                break;
            case MKA_UNAUTHENTICATED:
            default:
                /* Do nothing */
                break;
        }
    }
}

void MKA_LOGON_SetPortEnabled(t_MKA_bus bus, bool status)
{
    t_MKA_logon * const ctx = &mka_logon[bus];
    
    /* Check change to print info */
    if(ctx->port_enabled) {
        if(!status) {
            MKA_LOG_INFO("Logon instance[%d] link DOWN", bus);
        }
    }
    else {
        if(status) {
            MKA_LOG_INFO("Logon instance[%d] link UP", bus);
        }
    }

    ctx->port_enabled = status;
}

void MKA_LOGON_SetActivate(t_MKA_bus bus, t_MKA_activate activate)
{
    t_MKA_logon * const ctx = &mka_logon[bus];

    /* As stated in IEEE Std 802.1X-2020 Chapter 12.5.2 */
    if(ctx->logon && ctx->mka_enabled && ctx->mka_created) {
        if((ctx->activate == MKA_ACTIVATE_ONOPERUP) && (activate == MKA_ACTIVATE_ALWAYS)) {
            MKA_KAY_Participate(bus, true);
        }
        else if((ctx->activate == MKA_ACTIVATE_ALWAYS) && (activate == MKA_ACTIVATE_ONOPERUP)) {
            MKA_KAY_Participate(bus,false);
        }
        else {
            /* Do nothing */
        }
    }
    ctx->activate = activate;
}
