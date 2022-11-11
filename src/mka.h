/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka.h
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
 * @file        mka.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA public API
 *
 * @{
 */

#ifndef MKA_H_
#define MKA_H_

/*******************        Includes        *************************/

#include "mka_types.h"
#ifdef MKA_STANDALONE_COMPILATION
# include "mka_daemon_config.h"
#else
# include "mka_config.h"
#endif

/*lint -estring(1960, MKA_BUILD_DSA_PORT_NUMBER, MKA_GET_DSA_PORT_NUMBER, MKA_GET_ETHERTYPE_DSA_PORT_NUMBER) \
    [MISRA C++ 2008 Required Rule 16-0-4] Function-like macro for easier configuration */
/*lint -estring(9026, MKA_BUILD_DSA_PORT_NUMBER, MKA_GET_DSA_PORT_NUMBER, MKA_GET_ETHERTYPE_DSA_PORT_NUMBER) \
    [MISRA 2012 Directive 4.9, advisory] Function-like macro for easier configuration */

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/
/**
 * @brief Helper macro to create a port number in DSA mode that references
 *          a physical port of a particular switch in a given mode.
 *
 * @param[in] dsa_with_ethertype    Pass true if switch is using "Ethertype DSA", false otherwise.
 * @param[in] ethertype             Ethertype In ethertype DSA, ethertype to use for DSA packets.
 * @param[in] priority              DSA priority field.
 * @param[in] device                DSA device (switch ID assigned by bootstrap pins)
 * @param[in] port                  Physical port of the referenced device
 */
#define MKA_BUILD_DSA_PORT_NUMBER(dsa_with_ethertype, ethertype, priority, device, port) (\
    /* 0-3      physical port   */  ( (port) & 0xFU) | \
    /* 4-9      device ID       */  (((device) & 0x1FU) << 4U) | \
    /* 12-14    prio            */  (((priority) & 0x7U) << 12U) | \
    /* 15       mode            */  ( (dsa_with_ethertype) ? 0x8000U : 0U) | \
    /* 16-31    ethertype       */  ( ((ethertype) & 0xFFFFU) << 16U ) \
)

/**
 * @brief Helper macro to create a port number in standard DSA mode that references
 *          a physical port of a particular switch in a given mode.
 *
 * @param[in] priority              DSA priority field.
 * @param[in] device                DSA device (switch ID assigned by bootstrap pins)
 * @param[in] port                  Physical port of the referenced device
 */
#define MKA_GET_DSA_PORT_NUMBER(priority, device, port) \
    MKA_BUILD_DSA_PORT_NUMBER(false, 0U, priority, device, port)

/**
 * @brief Helper macro to create a port number in Ethertype DSA mode that references
 *          a physical port of a particular switch in a given mode.
 *
 * @param[in] ethertype             Ethertype In ethertype DSA, ethertype to use for DSA packets.
 * @param[in] priority              DSA priority field.
 * @param[in] device                DSA device (switch ID assigned by bootstrap pins)
 * @param[in] port                  Physical port of the referenced device
 */
#define MKA_GET_ETHERTYPE_DSA_PORT_NUMBER(ethertype, priority, device, port) \
    MKA_BUILD_DSA_PORT_NUMBER(true, ethertype, priority, device, port)

/*******************        Types             ***********************/

//NOTE: This configuration structure depends on OS system, so it cannot be
//      inside types file.

typedef enum {
    MKA_MACSEC_SOFTWARE,
    MKA_MACSEC_OFFLOADING,
    MKA_MACSEC_MEDIACONVERTER
} t_MACsec_mode;

/// Global configuration (no status variables included from IEEE802.1X data model)
typedef struct {
    uint32_t hello_time;              ///< MKA IEE802.1X timing: Hello time is the MKPDU period when a connection is established, applicable when delay_protect is disabled (milliseconds).
    uint32_t bounded_hello_time;      ///< MKA IEE802.1X timing: Hello time applicable with delay_protect (milliseconds).
    uint32_t life_time;               ///< MKA IEE802.1X timing: Life time for a peer to transmit MKPDU's in order to consider it alive (milliseconds)
    uint32_t sak_retire_time;         ///< MKA IEE802.1X timing: During a key rotation, time to retire the previous SAK key (milliseconds)
    uint32_t hello_rampup[MKA_MAX_RAMPUP_ELEMS];     ///< IEEE802.1X deviation to speed up linkup time (optionally defined). Periods between initial MKA messages after linkup (milliseconds)
    uint32_t hello_rampup_number;     ///< NUmber of used hello_rampup elements
    bool     transmit_empty_dist_sak; ///< Whether to transmit empty dist_sak when working without MACSEC.
    bool     transmit_empty_sak_use;  ///< Whether to transmit empty sak_use when working without MACSEC.
    /* NOTE: IEEE802.1X-2020 figure 11-16 note b states this parameter's PN as transmitted as zero when
    the cipher suite does not support extended packet number, which corresponds to setting "on". */
    bool     transmit_null_xpn;       ///< Whether to transmit a null XPN parameter when working without extended packet numbers.
    uint32_t secy_polling_ms;         ///< SecY polling period in milliseconds (MACSec statistics).
} t_MKA_global_config; 

/// Bus configuration (no status variables included from IEEE802.1X data model)
typedef struct {
    bool            enable;      ///< Individual bus enable
    // virtual ports not spuported

    struct {
        // EAP supplicant/authenticator not supported
        bool                mka;            ///< Initial MKA auto enable for this bus
        bool                macsec;         ///< MACSEC enable
        bool                announcements;  ///< Announcements enable (only secure announcements)
        bool                listener;       ///< Listener enable (only secure announcements)
    }                   port_capabilities;

    char const*         port_name;      ///< Bus name (OS / net stack). For DSA mode, prepend "dsa/" to interface.
    uint32_t            port_number;    ///< Port number (OS / net stack / SCI generation). For DSA mode use MKA_BUILD_DSA_PORT_NUMBER macro.

    char const*         controlled_port_name;     ///< MACSEC port name (OS/net stack)
    //uint16_t            controlled_port_number;   ///< MACSEC port number (OS/net stack)
    //char const*         uncontrolled_port_name;   ///< plain port name (OS/net stack)
    //uint16_t            uncontrolled_port_number; ///< plain port number (OS/net stack)

    struct {
        // groups not supported
        // suspension not supported
        // "participant" is a status variable
        bool                enable;             ///< Initial KAY enable for this bus
        uint8_t             actor_priority;     ///< Default actor priority
        t_MKA_role          actor_role;         ///< Actor role (key server, key client or auto)
        t_MKA_macsec_cap    macsec_capable;     ///< MACSEC capability for this bus
        bool                macsec_desired;     ///< Whether MACSEC is desired in this bus
        bool                replay_protect;     ///< Replay protect as used by CP-state machine
        uint32_t            replay_protect_wnd; ///< Replay protect window as used by CP-state machine
        bool                delay_protect;      ///< Delay protection

        t_MKA_activate      pcpt_activation;    ///< Activation of the participant
    }                   kay;

    struct {
        // useEAP not supported
        t_MKA_unauth_allow  unauth_allowed;     ///< Unauthenticated access allowed
        t_MKA_unsec_allow   unsecure_allowed;   ///< Unsecure access allowed
    }                   logon_nid;

    // announcements pending
    
    struct {
        bool                logon;              ///< Initial logon process enabled for this bus (MKA)

    }                   logon_process;

    // implementation specific
    struct {
        // PHY driver
        t_MKA_PhyDrv_config     phy_driver;
        // Key Management
        t_MKA_KeyMng            key_mng;

        // Cipher preference (non-present ciphers shall not be allowed)
        uint64_t                cipher_preference[5U];

        // Confidentiality offset preference (as key server; offset 0, offset 30 or offset 50)
        t_MKA_confidentiality_offset
                                conf_offset_preference;
        // Hardware offload
        t_MACsec_mode           mode;

        // Media converter UART interface
        char const*             mc_uart;

        // PHY settings (only applicable for Media Converter for now)
        t_MKA_PhyDrv_settings   phy_settings;

        // Interface mode, static or dynamic - Only applies to Linux
        t_MKA_intf_mode         intf_mode;
    }                   impl;
} t_MKA_bus_config;

/// MKA configuration, includes global and per bus configuration
typedef struct {
    t_MKA_global_config global_config;          ///< MKA Global Configuration
    t_MKA_bus_config bus_config[MKA_NUM_BUSES]; ///< MKA per bus configuration
} t_MKA_config;

/*******************        Variables         ***********************/
#if MKA_CFG_LOG_TO_BUFFER == MKA_ON // for quick debugging purposes only
extern char mka_debug_buffer[MKA_CFG_LOG_LINE_COUNT][MKA_LOG_MAXLENGTH];
extern uint32_t mka_debug_buffer_idx; // 0..(MKA_CFG_LOG_LINE_COUNT-1)
#endif
extern t_MKA_config MKA_config;

/*******************        Func. prototypes  ***********************/

/*lint -sem(MKA_Init, 1p==1) */
/**
 * Initialise MKA using the provided bus configuration.
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] cfg MKA configuration
 */
void MKA_Init(t_MKA_config const* cfg);

/**
 * Cyclic tasks for MKA functionality.
 *
 */
void MKA_MainFunction(void);

/*lint -sem(MKA_SetEnable, 1n<MKA_NUM_BUSES && 2n<2) */
/**
 * Enable MKA/MACSEC functionality in a given bus
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] status Enable/Disable functionality
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_SetEnable(t_MKA_bus bus, bool status);

/*lint -sem(MKA_GetEnable, 2p, 1n<MKA_NUM_BUSES) */
/**
 * Get whether the given bus is enabled
 * @remark Reentrant and thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[out] status Pointer to store retrieved status
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_GetEnable(t_MKA_bus bus, bool *status);

/*lint -sem(MKA_SetPortEnabled, 1n<MKA_NUM_BUSES && 2n<2) */
/**
 * Set Port Status(LinkUp/Down) for a given bus
 * @remark Reentrant and thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] status Bool indicating LinkUp/Down
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_SetPortEnabled(t_MKA_bus bus, bool status);

/*lint -sem(MKA_GetMacSecStats, 2p, 3p, 4p, 5p, 1n<MKA_NUM_BUSES && 2p==1 && 3p==1 && 4p==1 && 5p==1) */
/**
 * Function to retrieve MacSec statistics
 * @remark Reentrant and thread safe.
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
t_MKA_result MKA_GetMacSecStats(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy,
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc);

/*lint -sem(MKA_GetBusInfo, 2p, 1n<MKA_NUM_BUSES && 2p>=1) */
/**
 * Returns the MKA status for a given bus.
 * @remark Reentrant and thread safe.
 *
 * @param[in] bus Bus number
 * @param[out] info Bus status information
 *
 * @return MKA_OK       Status update to incoming structure.
 * @return MKA_NOT_OK   Status update error; invalid bus.
 */
t_MKA_result MKA_GetBusInfo(t_MKA_bus bus, t_MKA_bus_info* info);

/*******************        Func. definition  ***********************/

#ifdef __cplusplus
}
#endif

#endif /* MKA_H_ */

/** @} */

