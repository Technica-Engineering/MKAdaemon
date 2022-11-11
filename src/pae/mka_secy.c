/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_secy.c
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
 * @file        mka_secy.c
 * @version     1.0.0
 * @author      Ferran Pedrera
 * @brief       SecY implementation (802.1AE 2018)
 *
 * @{ 
 */

/*******************        Includes        *************************/

#include "mka_secy.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_DBUS
#include "dbus_server.h"
#endif

/*******************        Defines           ***********************/

/*! @brief Number of SAs statically allocated for TX and RX */
#define NUM_SAS  2U

/*! @brief Invalid SCI char to indicate a SC is free */
#define INVALID_SCI_CHAR  0xFF

/*! @brief Invalid association number to indicate a SA is free */
#define INVALID_AN  0xFFU

/*! @brief Hash length */
#define HASH_LEN  16U

/*! @brief Salt length */
#define SALT_LEN  12U

/*******************        Types             ***********************/

/*! @brief Struct storing Keys related data */
typedef struct {
    t_MKA_key SAK;
    t_MKA_key HASH;
    t_MKA_key SALT;
    t_MKA_ki key_identifier;
    bool transmits;
    bool receives;
    bool in_use_tx;
    bool in_use_rx;
    uint32_t installation_time;
} t_MKA_data_key;

/*! @brief Struct MacSec statistics */
typedef struct {
    t_MKA_stats_transmit_secy   stats_tx_secy;
    t_MKA_stats_receive_secy    stats_rx_secy;
    t_MKA_stats_transmit_sc     stats_tx_sc;
    t_MKA_stats_receive_sc      stats_rx_sc;
    bool                        stats_valid;
} t_MKA_stats;

/*! @brief Struct storing SecY data */
typedef struct {
    t_MKA_SECY_config   secy_config;
    t_MKA_transmit_sc   tx_sc;
    t_MKA_receive_sc    rx_sc;
    t_MKA_transmit_sa   tx_sa[NUM_SAS];
    t_MKA_receive_sa    rx_sa[NUM_SAS];
    t_MKA_data_key      data_key;
    t_MKA_stats         stats;
    t_mka_timer         polling_timer;
} t_MKA_secy;

/*******************        Variables         ***********************/

/*! @brief Array storing data for SecY instances */
static t_MKA_secy mka_secy[MKA_NUM_BUSES];

/*******************        Func. prototypes  ***********************/

/**
 * Function to check if a Secure Channel is free by checking SCI.
 * The 64-bit value FF-FF-FF-FF-FF-FF-FF-FF is never used as an SCI and is reserved for use by
 * implementations to indicate the absence of an SC or an SCI in contexts where an SC can be present.
 * reentrancy: Reentrant.
 * 
 * @param[in] sci: Struct pointer with SCI to be checked
 * @return true  Secure Channel free
 * @return false Secure Channel busy
 */
static bool CheckSCFree(t_MKA_sci const * sci);

/**
 * Function to get next Tx SA free slot. If AN is 0xFF, it is considered free.
 * reentrancy: Reentrant.
 * 
 * @param[in] sa: SA array pointer to be checked
 * @return First free slot.
 */
static uint8_t CheckNextTxSAFree(t_MKA_transmit_sa const * sa);

/**
 * Function to get next Rx SA free slot. If AN is 0xFF, it is considered free.
 * reentrancy: Reentrant.
 * 
 * @param[in] sa: SA array pointer to be checked
 * @return First free slot.
 */
static uint8_t CheckNextRxSAFree(t_MKA_receive_sa const * sa);

/*******************        Func. definition  ***********************/

static bool CheckSCFree(t_MKA_sci const * sci)
{
    bool ret = false;
    t_MKA_sci invalid_sci;

    memset(&invalid_sci, INVALID_SCI_CHAR, sizeof(t_MKA_sci));
    if(memcmp(&invalid_sci,sci,sizeof(t_MKA_sci)) == 0) {
        ret = true;
    }

    return ret;
}

static uint8_t CheckNextTxSAFree(t_MKA_transmit_sa const * sa)
{
    uint8_t i;

    for (i = 0;i < NUM_SAS;i++) {
        if(sa[i].an == INVALID_AN) {
            break;
        }
    }
    return i;
}

static uint8_t CheckNextRxSAFree(t_MKA_receive_sa const * sa)
{
    uint8_t i;

    for (i = 0;i < NUM_SAS;i++) {
        if(sa[i].an == INVALID_AN) {
            break;
        }
    }
    return i;
}

void MKA_SECY_Init(t_MKA_bus bus)
{
    t_MKA_secy * const ctx = &mka_secy[bus];

    /* Reset and set default values for context data */
    memset(ctx, 0, sizeof(t_MKA_secy));

    /* SC with SCI set to 0xFFs considered free */
    memset(&ctx->tx_sc.sci, INVALID_SCI_CHAR, sizeof(t_MKA_sci));
    memset(&ctx->rx_sc.sci, INVALID_SCI_CHAR, sizeof(t_MKA_sci));

    /* SA with AN set to 0xFF considered free */
    for(uint8_t i = 0; i< NUM_SAS; i++) {
        ctx->tx_sa[i].an = INVALID_AN;
        ctx->rx_sa[i].an = INVALID_AN;
    }

    ctx->secy_config.protect_frames = false;
    ctx->secy_config.replay_protect = false;
    ctx->secy_config.replay_window = 0;
    ctx->secy_config.validate_frames = MKA_VALIDATE_NULL;
    ctx->secy_config.current_cipher_suite = MKA_CS_NULL;
    ctx->secy_config.confidentiality_offset = MKA_CONFIDENTIALITY_NONE;
    ctx->secy_config.controlled_port_enabled = false;

    /* Start SecY timer to execute polling actions MainFunction */
    mka_timer_start(&ctx->polling_timer, MKA_active_global_config->secy_polling_ms + (((uint32_t)bus*MKA_active_global_config->secy_polling_ms)/MKA_NUM_BUSES_CONFIGURED));
}

void MKA_SECY_MainFunction(t_MKA_bus bus)
{
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];

    if(mka_timer_expired(&ctx->polling_timer)) {
        if(MKA_OK == cfg->impl.phy_driver.GetMacSecStats(bus, &ctx->stats.stats_tx_secy, &ctx->stats.stats_rx_secy, &ctx->stats.stats_tx_sc, &ctx->stats.stats_rx_sc)) {
            ctx->stats.stats_valid = true;
#ifdef ENABLE_DBUS
            dbus_update_statistics(bus, &ctx->stats.stats_tx_secy, &ctx->stats.stats_rx_secy, &ctx->stats.stats_tx_sc, &ctx->stats.stats_rx_sc);
#endif
        }
        else {
            ctx->stats.stats_valid = false;
        }

        /* Restart polling timer */
        mka_timer_start(&ctx->polling_timer, MKA_active_global_config->secy_polling_ms);
    }
}

t_MKA_result MKA_SECY_UpdateConfiguration(t_MKA_bus bus, t_MKA_SECY_config const * config)
{
    t_MKA_result ret = MKA_NOT_OK;
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];

    /* Check NULL configuration */
    if(NULL != config) {
        /* Avoid calling driver if config remains the same */
        if(memcmp(&ctx->secy_config, config, sizeof(t_MKA_SECY_config)) != 0) {
            if(MKA_OK == cfg->impl.phy_driver.UpdateSecY(bus, config, &ctx->tx_sc.sci)) {
                ret = MKA_OK;
                memcpy(&ctx->secy_config, config, sizeof(t_MKA_SECY_config));
            }
        }
    }
    else {
        MKA_LOG_ERROR("Null configuration on bus: %d", bus);
    }

    return ret;
}

void* MKA_SECY_InstallKey(t_MKA_bus bus, t_MKA_key const*sak, t_MKA_ki const*ki, bool transmit, bool receive)
{
    void* ret = NULL;
    void* encrypt = NULL;
    uint8_t zero_plaintext[HASH_LEN] = {0U};
    t_MKA_data_key * const ctx = &mka_secy[bus].data_key;

    /* Check SAK and Key Identifier are not NULL*/
    if((NULL != sak) && (NULL != ki)) {
        /* Start HASH calculation */
        encrypt = aes_encrypt_init(sak->key, sak->length);
        if(NULL == encrypt) {
            MKA_LOG_ERROR("Init Encrypt error during Key Installation on bus: %d", bus);
        }
        else if(0 != aes_encrypt(encrypt, zero_plaintext, &ctx->HASH.key[0])) {
            MKA_LOG_ERROR("Encrypt error during Tx SA creation on bus: %d", bus);
        }
        else {
            /* Copy SAK and KI */
            memcpy(&ctx->SAK, sak, sizeof(t_MKA_key));
            memcpy(&ctx->key_identifier, ki, sizeof(t_MKA_ki));
            /* SALT calculation */
            for (uint8_t i = 0U; i < 8U; i++) {
                ctx->SALT.key[i] = ctx->key_identifier.mi[i];
            }
            ctx->SALT.key[8] = ctx->key_identifier.mi[8] ^ (uint8_t)((ctx->key_identifier.kn & 0xFF000000U) >> 24U);
            ctx->SALT.key[9] = ctx->key_identifier.mi[9] ^ (uint8_t)((ctx->key_identifier.kn & 0x00FF0000U) >> 16U);
            ctx->SALT.key[10]= ctx->key_identifier.mi[10]^ (uint8_t)((ctx->key_identifier.kn & 0x0000FF00U) >> 8U);
            ctx->SALT.key[11]= ctx->key_identifier.mi[11]^ (uint8_t) (ctx->key_identifier.kn & 0x000000FFU);

            ctx->HASH.length = HASH_LEN;
            ctx->SALT.length = SALT_LEN;

            ctx->transmits = transmit;
            ctx->receives = receive;
            ctx->in_use_tx = false;
            ctx->in_use_rx = false;
            ctx->installation_time = mka_tick_time_ms;

            ret = ctx;
        }

        /* Free encrypt resource if needed */
        if(NULL != encrypt) {
            aes_encrypt_deinit(encrypt);
        }

    }
    else {
        MKA_LOG_ERROR("Null SAK or KI on bus: %d", bus);
    }

    return ret;
}

t_MKA_transmit_sc* MKA_SECY_CreateTransmitSC(t_MKA_bus bus, t_MKA_sci const* sci)
{
    t_MKA_transmit_sc* ret = NULL;
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    uint32_t timestamp;
    
    /* Check SCI not NULL */
    if(NULL != sci) {
        if(CheckSCFree(&ctx->tx_sc.sci)) {
            /* Update SecY with new SCI to driver */
            if(MKA_OK == cfg->impl.phy_driver.UpdateSecY(bus, &ctx->secy_config, sci)) {
                /* Reset SC data and save new parameters */
                memset(&ctx->tx_sc, 0, sizeof(t_MKA_transmit_sc));
                ctx->tx_sc.sc_stats = &ctx->stats.stats_tx_sc;
                ctx->tx_sc.transmitting = false;
                memcpy(&ctx->tx_sc.sci, sci, sizeof(t_MKA_sci));
                timestamp = mka_tick_time_ms;
                ctx->tx_sc.created_time = timestamp;
                ctx->tx_sc.started_time = timestamp;
                ctx->tx_sc.stopped_time = timestamp;

                ret = &ctx->tx_sc;
            }
            else {
                MKA_LOG_ERROR("Error updating SecY on bus: %d", bus);
            }
        }
        else {
            MKA_LOG_WARNING("TX SC already created on bus: %d", bus);
        }
    }
    else {
        MKA_LOG_ERROR("Null SCI on bus: %d", bus);
    }

    return ret;
}

void MKA_SECY_DestroyTransmitSC(t_MKA_bus bus, t_MKA_transmit_sc* sc)
{
    t_MKA_secy const * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];

    if(NULL != sc) {
        /* Delete TX SC in phy */
        (void)cfg->impl.phy_driver.UpdateSecY(bus, &ctx->secy_config, NULL); /* NULL TX SCI means delete TX SC */
        memset(sc, 0, sizeof(t_MKA_transmit_sc));
        /* Mark SC as free */
        memset(&sc->sci, INVALID_SCI_CHAR, sizeof(t_MKA_sci));
    }
    else {
        MKA_LOG_ERROR("Null SC on bus: %d", bus);
    }
}

t_MKA_receive_sc* MKA_SECY_CreateReceiveSC(t_MKA_bus bus, t_MKA_sci const* sci)
{
    t_MKA_receive_sc* ret = NULL;
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    uint32_t timestamp;

    /* Check SCI not NULL */
    if(NULL !=sci) {
        if(CheckSCFree(&ctx->rx_sc.sci)) {
            if(MKA_OK == cfg->impl.phy_driver.InitRxSC(bus, sci)) {
                memset(&ctx->rx_sc, 0, sizeof(t_MKA_receive_sc));
                memcpy(&ctx->rx_sc.sci, sci, sizeof(t_MKA_sci));
                ctx->rx_sc.sc_stats = &ctx->stats.stats_rx_sc;
                ctx->rx_sc.receiving = false;
                timestamp = mka_tick_time_ms;
                ctx->rx_sc.created_time = timestamp;
                ctx->rx_sc.started_time = timestamp;
                ctx->rx_sc.stopped_time = timestamp;

                ret = &ctx->rx_sc;
            }
            else {
                MKA_LOG_ERROR("Error creating RX SC on bus: %d", bus);
            }
        }
        else {
            MKA_LOG_WARNING("RX SC already created on bus: %d", bus);
        }
    }
    else {
        MKA_LOG_ERROR("Null SCI on bus: %d", bus);
    }
    
    return ret;
}


void MKA_SECY_DestroyReceiveSC(t_MKA_bus bus, t_MKA_receive_sc* sc)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];

    if(NULL != sc) {
        /* Delete RX SC in phy */
        (void)cfg->impl.phy_driver.DeinitRxSC(bus, &sc->sci);
        memset(sc, 0, sizeof(t_MKA_transmit_sc));
        /* Mark SC as free */
        memset(&sc->sci, INVALID_SCI_CHAR, sizeof(t_MKA_sci));
    }
    else {
        MKA_LOG_ERROR("Null SC on bus: %d", bus);
    }
}

t_MKA_transmit_sa* MKA_SECY_CreateTransmitSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_confidentiality_offset co, void* sak)
{
    t_MKA_transmit_sa* ret = NULL;
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    uint8_t idx = CheckNextTxSAFree(&ctx->tx_sa[0]);
    uint32_t timestamp;

    /* Check free TX SA */
    if(idx<NUM_SAS) {
        if(NULL != sak) {
            //lint -e{9079, 9087} [MISRA 2012 Rule 11.5, advisory] Pointer cast is unavoidable
            t_MKA_data_key const * const data_key = (t_MKA_data_key*)sak;
            if(data_key->transmits) {
                /* Reset data and save parameters */
                memset(&ctx->tx_sa[idx], 0, sizeof(t_MKA_transmit_sa));
                ctx->tx_sa[idx].in_use = false;
                ctx->tx_sa[idx].ssci = ssci;
                ctx->tx_sa[idx].confidentiality = co;
                ctx->tx_sa[idx].next_pn = next_pn;
                ctx->tx_sa[idx].an = an;
                ctx->tx_sa[idx].data_key = sak;
                ctx->tx_sa[idx].enable_transmit = false;
                /* Set PHY TX SA configuration */
                if(MKA_OK == cfg->impl.phy_driver.AddTxSA(bus, an, next_pn, 0U, &data_key->SAK, &data_key->HASH, &data_key->SALT, &data_key->key_identifier, false)) {
                    /* Save initial timestamps */
                    timestamp = mka_tick_time_ms;
                    ctx->tx_sa[idx].created_time = timestamp;
                    ctx->tx_sa[idx].started_time = timestamp;
                    ctx->tx_sa[idx].stopped_time = timestamp;

                    ret = &ctx->tx_sa[idx];
                }
                else {
                    MKA_LOG_ERROR("Error creating TX SA on bus: %d", bus);
                }
            }
            else {
                MKA_LOG_WARNING("SAK not enabled for transmission on bus: %d", bus);
            }
        }
        else {
            MKA_LOG_ERROR("Null SAK on bus: %d", bus);
        }
    }
    else {
        MKA_LOG_WARNING("All TX SAs busy on bus: %d", bus);
    }

    return ret;
}

void MKA_SECY_DestroyTransmitSA(t_MKA_bus bus, t_MKA_transmit_sa* sa)
{
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    bool disable_transmitting = true;

    if(NULL != sa) {
        (void)cfg->impl.phy_driver.DeleteTxSA(bus, sa->an);
        /* Disable TX SC if no TX SA is in use */
        for(uint8_t i = 0; i< NUM_SAS; i++) {
            if((&ctx->tx_sa[i] != sa) && ctx->tx_sa[i].in_use) {
                disable_transmitting = false;
            }
        }
        if(disable_transmitting && ctx->tx_sc.transmitting) {
            ctx->tx_sc.transmitting = false;
            ctx->tx_sc.stopped_time = mka_tick_time_ms;
        }
        memset(sa, 0, sizeof(t_MKA_transmit_sa));
        sa->an = INVALID_AN;
    }
    else {
        MKA_LOG_ERROR("Null SA on bus: %d", bus);
    }
}

t_MKA_receive_sa* MKA_SECY_CreateReceiveSA(t_MKA_bus bus, uint8_t an, t_MKA_pn lowest_pn, t_MKA_ssci ssci, void* sak)
{
    t_MKA_receive_sa* ret = NULL;
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    uint8_t idx = CheckNextRxSAFree(&ctx->rx_sa[0]);
    uint32_t timestamp;

    /* Check free RX SA */
    if(idx<NUM_SAS) {
        if(NULL != sak) {
            //lint -e{9079, 9087} [MISRA 2012 Rule 11.5, advisory] Pointer cast is unavoidable
            t_MKA_data_key const * const data_key = (t_MKA_data_key*)sak;
            if(data_key->receives) {
                /* Reset data and save parameters */
                memset(&ctx->rx_sa[idx], 0, sizeof(t_MKA_transmit_sa));
                ctx->rx_sa[idx].in_use = false;
                ctx->rx_sa[idx].ssci = ssci;
                ctx->rx_sa[idx].next_pn = lowest_pn;
                ctx->rx_sa[idx].lowest_pn = lowest_pn;
                ctx->rx_sa[idx].an = an;
                ctx->rx_sa[idx].data_key = sak;
                ctx->rx_sa[idx].enable_receive = false;
                /* Set PHY RX SA configuration */
                if(MKA_OK == cfg->impl.phy_driver.AddRxSA(bus, an, lowest_pn, 0U, &data_key->SAK, &data_key->HASH, &data_key->SALT, &data_key->key_identifier, false)) {
                    /* Save initial timestamps */
                    timestamp = mka_tick_time_ms;
                    ctx->rx_sa[idx].created_time = timestamp;
                    ctx->rx_sa[idx].started_time = timestamp;
                    ctx->rx_sa[idx].stopped_time = timestamp;

                    ret = &ctx->rx_sa[idx];
                }
                else {
                    MKA_LOG_ERROR("Error creating RX SA on bus: %d", bus);
                }
            }
            else {
                MKA_LOG_WARNING("SAK not enabled for reception on bus: %d", bus);
            }
        }
        else {
            MKA_LOG_ERROR("Null SAK on bus: %d", bus);
        }
    }
    else {
        MKA_LOG_WARNING("All RX SAs busy on bus: %d", bus);
    }

    return ret;
}

void MKA_SECY_DestroyReceiveSA(t_MKA_bus bus, t_MKA_receive_sa* sa)
{
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    bool disable_receiving = true;

    if(NULL != sa) {
        (void)cfg->impl.phy_driver.DeleteRxSA(bus, sa->an);
        /* Disable RX SC if no RX SA is in use */
        for(uint8_t i = 0; i< NUM_SAS; i++) {
            if((&ctx->rx_sa[i] != sa) && ctx->rx_sa[i].in_use) {
                disable_receiving = false;
            }
        }
        if(disable_receiving && ctx->rx_sc.receiving) {
            ctx->rx_sc.receiving = false;
            ctx->rx_sc.stopped_time = mka_tick_time_ms;
        }
        memset(sa, 0, sizeof(t_MKA_receive_sa));
        sa->an = INVALID_AN;
    }
    else {
        MKA_LOG_ERROR("Null SA on bus: %d", bus);
    }
}

t_MKA_result MKA_SECY_TransmitSA_EnableTransmit(t_MKA_bus bus, t_MKA_transmit_sa*sa)
{
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_MKA_result result = MKA_NOT_OK;

    if(NULL != sa) {
        //lint -e{9079, 9087} [MISRA 2012 Rule 11.5, advisory] Pointer cast is unavoidable
        t_MKA_data_key * const data_key = (t_MKA_data_key*)sa->data_key;

        if(!sa->enable_transmit) {
            sa->enable_transmit = true;
            result = cfg->impl.phy_driver.UpdateTxSA(bus, sa->an, sa->next_pn, sa->enable_transmit);
            if(MKA_OK == result) {
                uint32_t timestamp = mka_tick_time_ms;
                sa->in_use = true;
                sa->started_time = timestamp;
                /* Only ONE TX SA can be enabled at a time, stop the rest (already stopped by Driver API) */
                for(uint8_t i = 0; i< NUM_SAS; i++) {
                    if((&ctx->tx_sa[i] != sa) && ctx->tx_sa[i].in_use) {
                        ctx->tx_sa[i].enable_transmit = false;
                        ctx->tx_sa[i].in_use = false;
                        ctx->tx_sa[i].stopped_time = timestamp;
                    }
                }
                /* Clean SAK, HASH, SALT from RAM if already in use for RX & TX */
                data_key->in_use_tx = true;
                if(data_key->in_use_rx) {
                    memset(&data_key->SAK, 0, sizeof(t_MKA_key));
                    memset(&data_key->HASH, 0, sizeof(t_MKA_key));
                    memset(&data_key->SALT, 0, sizeof(t_MKA_key));
                    MKA_LOG_DEBUG0("Remove KEY from RAM on bus: %d", bus);
                }

                /* Enable transmitting for this channel if it is the first TX SA in use */
                if(!ctx->tx_sc.transmitting) {
                    ctx->tx_sc.transmitting = true;
                    ctx->tx_sc.started_time = timestamp;
                }
            }
            else {
                MKA_LOG_ERROR("Error updating TX SA on bus: %d", bus);
            }
        }
        else {
            MKA_LOG_WARNING("SA already enabled for transmission on bus: %d", bus);
            result = MKA_OK; // not an actual error
        }
    }
    else {
        MKA_LOG_ERROR("Null SA on bus: %d", bus);
    }

    return result;
}

t_MKA_result MKA_SECY_ReceiveSA_EnableReceive(t_MKA_bus bus, t_MKA_receive_sa*sa)
{
    t_MKA_secy * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_MKA_result result = MKA_NOT_OK;

    if(NULL != sa) {
        //lint -e{9079, 9087} [MISRA 2012 Rule 11.5, advisory] Pointer cast is unavoidable
        t_MKA_data_key * const data_key = (t_MKA_data_key*)sa->data_key;

        if(!sa->enable_receive) {
            sa->enable_receive = true;
            result = cfg->impl.phy_driver.UpdateRxSA(bus, sa->an, sa->next_pn, sa->enable_receive);
            if(MKA_OK == result) {
                uint32_t timestamp = mka_tick_time_ms;
                sa->in_use = true;
                sa->started_time = timestamp;
                /* Clean SAK, HASH, SALT from RAM if already in use for RX & TX */
                data_key->in_use_rx = true;
                if(data_key->in_use_tx) {
                    memset(&data_key->SAK, 0, sizeof(t_MKA_key));
                    memset(&data_key->HASH, 0, sizeof(t_MKA_key));
                    memset(&data_key->SALT, 0, sizeof(t_MKA_key));
                    MKA_LOG_DEBUG0("Remove KEY from RAM on bus: %d", bus);
                }
                /* Enable receiveing for this channel if it is the first RX SA in use */
                if(!ctx->rx_sc.receiving) {
                    ctx->rx_sc.receiving = true;
                    ctx->rx_sc.started_time = timestamp;
                }
            }
            else {
                MKA_LOG_ERROR("Error updating RX SA on bus: %d", bus);
            }
        }
        else {
            MKA_LOG_WARNING("SA already enabled for reception on bus: %d", bus);
            result = MKA_OK; // not an actual error
        }
    }
    else {
        MKA_LOG_ERROR("Null SA on bus: %d", bus);
    }

    return result;
}

void MKA_SECY_ReceiveSA_UpdateNextPN(t_MKA_bus bus, t_MKA_receive_sa*sa, t_MKA_pn next_pn)
{
    t_MKA_secy const * const ctx = &mka_secy[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];

    if(NULL != sa) {
        if(MKA_OK != cfg->impl.phy_driver.UpdateRxSA(bus, sa->an, next_pn, sa->enable_receive)) {
            MKA_LOG_ERROR("Error updating RX NextPN on bus: %d", bus);
        }
        else {
            sa->next_pn = next_pn;
            if(next_pn > ctx->secy_config.replay_window) {
                sa->lowest_pn = next_pn - ctx->secy_config.replay_window;
            }
            else {
                sa->lowest_pn = 1;
            }
        }
    }
    else {
        MKA_LOG_ERROR("Null SA on bus: %d", bus);
    }   
}

t_MKA_result MKA_SECY_TransmitSA_UpdateNextPN(t_MKA_bus bus, t_MKA_transmit_sa*sa)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_MKA_pn next_pn;
    t_MKA_result ret = MKA_NOT_OK;

    if(NULL != sa) {
        if(MKA_OK == cfg->impl.phy_driver.GetTxSANextPN(bus, sa->an, &next_pn)) {
            sa->next_pn = next_pn;
            ret = MKA_OK;
        }
    }
    else {
        MKA_LOG_ERROR("Null SA on bus: %d", bus);
    }

    return ret;
}

/**
 * Function to retrieve MacSec statistics
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[out] stats_tx_secy: Pointer to store Tx SecY statistics
 * @param[out] stats_rx_secy: Pointer to store Rx SecY statistics
 * @param[out] stats_tx_sc: Pointer to store Tx SC statistics
 * @param[out] stats_rx_sc: Pointer to store Rx SC statistics
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_SECY_GetMacSecStats(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy,
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc)
{
    t_MKA_secy const * const ctx = &mka_secy[bus];
    t_MKA_result ret = MKA_NOT_OK;

    /* Only copy stats if valid */
    if(ctx->stats.stats_valid) {
        MKA_CRITICAL_ENTER();
        memcpy(stats_tx_secy, &ctx->stats.stats_tx_secy, sizeof(t_MKA_stats_transmit_secy));
        memcpy(stats_rx_secy, &ctx->stats.stats_rx_secy, sizeof(t_MKA_stats_receive_secy));
        memcpy(stats_tx_sc, &ctx->stats.stats_tx_sc, sizeof(t_MKA_stats_transmit_sc));
        memcpy(stats_rx_sc, &ctx->stats.stats_rx_sc, sizeof(t_MKA_stats_receive_sc));
        MKA_CRITICAL_LEAVE();
        ret = MKA_OK;
    }

    return ret;
}
