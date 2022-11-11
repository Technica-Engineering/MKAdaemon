/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_phy_drv.h
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
 * @file        mka_phy_drv.h
 * @version     1.0.0
 * @author      Ferran Pedrera
 * @brief       MKA phy driver interface
 *
 * @{
 */

#ifndef MKA_PHY_DRV_H_
#define MKA_PHY_DRV_H_

/*******************        Includes        *************************/

#include "mka.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

/**
 * Function to Init MACSEC PHY.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_InitMacSec(t_MKA_bus bus);

/**
 * Function to update PHY SecY.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] config: Pointer to SecY configuration.
 * @param[in] tx_sci: SCI used to create TX Secure Channel
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_UpdateSecY(t_MKA_bus bus, t_MKA_SECY_config const * config, t_MKA_sci const * tx_sci);

/**
 * Function to deinit MACSEC PHY.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_DeinitMacSec(t_MKA_bus bus);

/**
 * Function to create PHY Reception Secure Channel.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sci: SCI used to create RX Secure Channel
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_InitRxSC(t_MKA_bus bus, t_MKA_sci const * sci);

/**
 * Function to update PHY Reception Secure Channel.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sci: SCI used to create RX Secure Channel
 */
t_MKA_result MKA_PHY_UpdateRxSC(t_MKA_bus bus, t_MKA_sci const * sci);

/**
 * Function to delete PHY Reception Secure Channel.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sci: SCI used to create RX Secure Channel
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_DeinitRxSC(t_MKA_bus bus, t_MKA_sci const * sci);

/**
 * Function to create PHY Transmission Secure Association.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number for the created Secure Association
 * @param[in] next_pn: nextPN for the created Secure Association
 * @param[in] ssci: SSCI parameter for the created Secure Association
 * @param[in] sak: SAK pointer to be used for the created Secure Association
 * @param[in] hash: HASH pointer to be used for the created Secure Association
 * @param[in] salt: SALT pointer to be used for the created Secure Association
 * @param[in] active: Boolean flag to enable or disable the created Secure Association
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_AddTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active);

/**
 * Function to update PHY Transmission Secure Association.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number identifiying a Secure Association
 * @param[in] next_pn: nextPN for to update Secure Association
 * @param[in] active: Boolean flag to enable or disable the Secure Association
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_UpdateTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active);

/**
 * Function to delete PHY Transmission Secure Association.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number identifiying a Secure Association
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_DeleteTxSA(t_MKA_bus bus, uint8_t an);

/**
 * Function to create PHY Reception Secure Association.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number for the created Secure Association
 * @param[in] next_pn: nextPN for the created Secure Association
 * @param[in] ssci: SSCI parameter for the created Secure Association
 * @param[in] sak: SAK pointer to be used for the created Secure Association
 * @param[in] hash: HASH pointer to be used for the created Secure Association
 * @param[in] salt: SALT pointer to be used for the created Secure Association
 * @param[in] active: Boolean flag to enable or disable the created Secure Association
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_AddRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active);

/**
 * Function to update PHY Reception Secure Association.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number identifiying a Secure Association
 * @param[in] next_pn: nextPN for to update Secure Association
 * @param[in] active: Boolean flag to enable or disable the Secure Association
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_UpdateRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active);

/**
 * Function to delete PHY Reception Secure Association.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number identifiying a Secure Association
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_DeleteRxSA(t_MKA_bus bus, uint8_t an);

/**
 * Function to retrieve nextPN for a transmission Secure Association.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number identifiying a Secure Association
 * @param[out] next_pn: Retrieved nextPN
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_PHY_GetTxSANextPN(t_MKA_bus bus, uint8_t an, t_MKA_pn* next_pn);

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
t_MKA_result MKA_PHY_GetMacSecStats(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy,
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc);

#ifdef __cplusplus
}
#endif

#endif // MKA_PHY_DRV_H_
