/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_main.c
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
 * @file        mka_main.c
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA main file
 *
 * @{
 */

/*******************        Includes        *************************/
#include "mka_private.h"
#if (MKA_RUNNING_OS == MKA_OS_FREERTOS_LWIP)
# include "FreeRTOS.h"
# include "task.h" // time getters
#elif (MKA_RUNNING_OS == MKA_OS_LINUX) || defined(UNIT_TEST)
# include <time.h>
#elif (MKA_RUNNING_OS == MKA_OS_AUTOSAR)
# include "Os.h"
#elif (MKA_RUNNING_OS == MKA_OS_MARVELL_SDK)
# include "app_api.h"
#else
# error "Unknown operating system."
#endif

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/
/// Time when execution tick starts.
uint32_t mka_tick_time_ms = 0U;
t_MKA_global_config const* MKA_active_global_config = NULL;
t_MKA_bus_config const* MKA_active_buses_config = NULL;

/*******************        Func. prototypes  ***********************/
static void mka_UpdateTicks(void);

/*******************        Func. definition  ***********************/
void MKA_Init(t_MKA_config const* cfg)
{
    t_MKA_bus bus;

    MKA_ASSERT(NULL != cfg, "MKA initialised with null configuration");

    // Very basic sanity check, hoping to catch some invalid configuration

    MKA_ASSERT(cfg->global_config.hello_time <= 100000U,
                        "MKA initialised with invalid 'hello_time'");
    MKA_ASSERT(cfg->global_config.bounded_hello_time <= 100000U,
                        "MKA initialised with invalid 'bounded_hello_time'");
    MKA_ASSERT(cfg->global_config.life_time <= 100000U,
                        "MKA initialised with invalid 'life_time'");
    MKA_ASSERT(cfg->global_config.sak_retire_time <= 100000U,
                        "MKA initialised with invalid 'sak_retire_time'");

    MKA_ASSERT(cfg->global_config.hello_rampup_number <= MKA_MAX_RAMPUP_ELEMS,
                        "MKA initialised with invalid 'hello_rampup_number'");

    for(uint32_t i=0U;i<cfg->global_config.hello_rampup_number;i++) {
        MKA_ASSERT(cfg->global_config.hello_rampup[i] <= 100000U,
                            "MKA initialised with invalid 'hello_rampup' in index %d", i);
    }

    for(bus=0U; bus<MKA_NUM_BUSES_CONFIGURED; ++bus) {
        //lint -save -e685 [MISRA 2012 Rule 14.3, required] these are just a sanity check, explicitly forcing compiler to compare
        MKA_ASSERT(NULL != cfg->bus_config[bus].port_name, "MKA initialised with NULL port for bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].kay.macsec_capable <= MKA_MACSEC_INT_CONF_0_30_50,
                                "MKA initialised with invalid 'macsec_capable' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].kay.pcpt_activation <= MKA_ACTIVATE_ALWAYS,
                                "MKA initalised with invalid 'activation' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].logon_nid.unauth_allowed <= MKA_UNAUTH_ON_AUTH_FAIL,
                                "MKA initalised with invalid 'unauth_allowed' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].logon_nid.unsecure_allowed <= MKA_UNSECURE_PER_MKA_SERVER,
                                "MKA initalised with invalid 'unauth_allowed' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.conf_offset_preference <= MKA_CONFIDENTIALITY_OFFSET_50,
                                "MKA initalised with invalid 'conf_offset_preference' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.UpdateSecY != NULL,
                        "MKA initalised with NULL Driver function 'UpdateSecY' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.InitRxSC != NULL,
                        "MKA initalised with NULL Driver function 'InitRxSC' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.DeinitRxSC != NULL,
                        "MKA initalised with NULL Driver function 'DeinitRxSC' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.AddTxSA != NULL,
                        "MKA initalised with NULL Driver function 'AddTxSA' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.UpdateTxSA != NULL,
                        "MKA initalised with NULL Driver function 'UpdateTxSA' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.DeleteTxSA != NULL,
                        "MKA initalised with NULL Driver function 'DeleteTxSA' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.AddRxSA != NULL,
                        "MKA initalised with NULL Driver function 'AddRxSA' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.UpdateRxSA != NULL,
                        "MKA initalised with NULL Driver function 'UpdateRxSA' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.DeleteRxSA != NULL,
                        "MKA initalised with NULL Driver function 'DeleteRxSA' on bus %i", bus);
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.GetTxSANextPN != NULL,
                        "MKA initalised with NULL Driver function 'GetTxSANextPN' on bus %i", bus); 
        MKA_ASSERT(cfg->bus_config[bus].impl.phy_driver.GetMacSecStats != NULL,
                        "MKA initalised with NULL Driver function 'GetMacSecStats' on bus %i", bus);      
        //lint -restore
    }

    MKA_active_global_config = &cfg->global_config;
    MKA_active_buses_config = &cfg->bus_config[0U];
    mka_tick_time_ms = 0U;

    mka_UpdateTicks();
    //crypto_global_init(); // TODO

    for(bus=0U; bus<MKA_NUM_BUSES_CONFIGURED; ++bus) {
        if(MKA_active_buses_config[bus].enable) {
            // L2 handled by KAY
    #ifdef MKA_MDIOAL
            MKA_ASSERT(MKA_OK == MKA_MDIOAL_init(bus), "Error initialising MDIOAL layer for bus %i", bus);
    #endif
            MKA_SECY_Init(bus);
            MKA_KAY_Init(bus);
            MKA_LOGON_Init(bus);
            MKA_CP_Init(bus);

            MKA_KAY_SetEnable(bus, cfg->bus_config[bus].kay.enable);
        }
    }
}

void MKA_MainFunction(void)
{
    t_MKA_bus bus;
    MKA_ASSERT(NULL != MKA_active_global_config, "MKA executing with null global configuration");
    MKA_ASSERT(NULL != MKA_active_buses_config, "MKA executing with null buses configuration");

    mka_UpdateTicks();

    for(bus=0U; bus<MKA_NUM_BUSES_CONFIGURED; ++bus) {
        if(MKA_active_buses_config[bus].enable) {
            MKA_LOGON_MainFunction(bus);
            MKA_KAY_MainFunctionReception(bus);
            MKA_KAY_MainFunctionTimers(bus);
            MKA_CP_MainFunction(bus);
            MKA_KAY_MainFunctionTransmission(bus);
            MKA_SECY_MainFunction(bus);
        }
    }
}

t_MKA_result MKA_SetEnable(t_MKA_bus bus, bool status)
{
    t_MKA_result ret = MKA_NOT_OK;

    if(bus < MKA_NUM_BUSES_CONFIGURED) {
        MKA_KAY_SetEnable(bus, status);
        ret = MKA_OK;
    }

    return ret;
}

t_MKA_result MKA_GetEnable(t_MKA_bus bus, bool *status)
{
    t_MKA_result ret = MKA_NOT_OK;

    if(bus < MKA_NUM_BUSES_CONFIGURED) {
        *status = MKA_KAY_GetEnable(bus);
        ret = MKA_OK;
    }

    return ret;
}

t_MKA_result MKA_SetPortEnabled(t_MKA_bus bus, bool status)
{
    t_MKA_result ret = MKA_NOT_OK;

    if(bus < MKA_NUM_BUSES_CONFIGURED) {
        /* Distribute Port status to different MKA modules */
        MKA_CP_SetPortEnabled(bus, status);
        MKA_LOGON_SetPortEnabled(bus, status);
        ret = MKA_OK;
    }

    return ret;
}

t_MKA_result MKA_GetMacSecStats(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy,
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc)
{
    t_MKA_result ret = MKA_NOT_OK;

    if( (bus < MKA_NUM_BUSES_CONFIGURED) &&
        (NULL!= stats_tx_secy) &&
        (NULL!= stats_rx_secy) &&
        (NULL!= stats_tx_sc) &&
        (NULL!= stats_rx_sc) ) {
        ret = MKA_SECY_GetMacSecStats(bus, stats_tx_secy, stats_rx_secy, stats_tx_sc, stats_rx_sc);
    }

    return ret;
}

t_MKA_result MKA_GetBusInfo(t_MKA_bus bus, t_MKA_bus_info* info)
{
    return (bus < MKA_NUM_BUSES) ? MKA_KAY_GetBusInfo(bus, info) : MKA_NOT_OK;
}

static void mka_UpdateTicks(void)
{
#if (MKA_RUNNING_OS == MKA_OS_FREERTOS_LWIP)
    mka_tick_time_ms = xTaskGetTickCount();

#elif (MKA_RUNNING_OS == MKA_OS_LINUX) || defined(UNIT_TEST)
    static struct timespec initial_tv = {0, 0};
    struct timespec current_tv, delta;
    MKA_ASSERT(0 == clock_gettime(CLOCK_MONOTONIC_RAW, &current_tv), "Error while getting system clock");

    if ((0 == initial_tv.tv_sec) && (0 == initial_tv.tv_nsec)) {
        memcpy(&initial_tv, &current_tv, sizeof(struct timespec));
    }

    delta.tv_sec = current_tv.tv_sec - initial_tv.tv_sec;
    delta.tv_nsec = current_tv.tv_nsec - initial_tv.tv_nsec;
    if (delta.tv_nsec < 0L) {
        --delta.tv_sec;
        delta.tv_nsec += 1000000000L;
    }

    mka_tick_time_ms = (delta.tv_sec * 1000U);
    mka_tick_time_ms += (delta.tv_nsec / 1000000U);

#elif (MKA_RUNNING_OS == MKA_OS_AUTOSAR) // OSEK
    {
        TickType ticks;
        (void)GetCounterValue(COUNTER_MS, &ticks); // TODO configurable ms counter
        mka_tick_time_ms = ticks;
    }

#elif (MKA_RUNNING_OS == MKA_OS_MARVELL_SDK)
    mka_tick_time_ms = APP_GetTimeMs();

#endif
}

#ifdef MKA_STANDALONE_COMPILATION
bool mka_AddSleepTime(struct timespec* max_wait)
{
    bool do_sleep;

    // Update time reference to now
    mka_UpdateTicks();

    // Check what timer expires first
    uint32_t how_much = mka_timer_maxsleep();

    if (how_much > 0U) {
        // Add it
        max_wait->tv_nsec += how_much * 1000000ULL;

        // Wrap-around ns
        max_wait->tv_sec += max_wait->tv_nsec / 1000000000ULL;
        max_wait->tv_nsec = max_wait->tv_nsec % 1000000000ULL;

        do_sleep = true;
    }
    else {
        do_sleep = false;
    }

    return do_sleep;
}
#endif


/** @} */


