/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_secy.h
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
 * @file        mka_secy.h
 * @version     1.0.0
 * @author      Ferran Pedrera
 * @brief       SECY definition (802.1AE 2018)
 *
 * @{
 */

#ifndef MKA_SECY_H_
#define MKA_SECY_H_

/*******************        Includes        *************************/

#include "mka_private.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/


/**
 * Initialises SecY module.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_SECY_Init(t_MKA_bus bus);

/**
 * Runs SECY module periodic function.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_SECY_MainFunction(t_MKA_bus bus);

/**
 * Function to update SECY configuration. To be used by CP module
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] config: SecY configuration pointer
 * 
 * @return t_MKA_result Configuration result
 */
t_MKA_result MKA_SECY_UpdateConfiguration(t_MKA_bus bus, t_MKA_SECY_config const * config);

/**
 * Function to install SAK key in SecY
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sak: Pointer to SAK key to be installed
 * @param[in] ki: Pointer to Key Identifier of provided SAK
 * @param[in] transmit: Installed key to be used for transmission
 * @param[in] receive: Installed key to be used for reception
 * 
 * @return Opaque pointer/reference to the installed key. NULL in case of failure.
 */
void* MKA_SECY_InstallKey(t_MKA_bus bus, t_MKA_key const*sak, t_MKA_ki const*ki, bool transmit, bool receive);

/**
 * Function to create a Transmission Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sci: Pointer to Secure Channel Identifier
 * 
 * @return Pointer/Reference to the created Secure Channel.
 */
t_MKA_transmit_sc* MKA_SECY_CreateTransmitSC(t_MKA_bus bus, t_MKA_sci const* sci);

/**
 * Function to delete a Transmission Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sc: Pointer/Reference to the Secure Channel to be deleted
 */
void MKA_SECY_DestroyTransmitSC(t_MKA_bus bus, t_MKA_transmit_sc* sc);

/**
 * Function to create a Reception Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sci: Pointer to Secure Channel Identifier
 * 
 * @return Pointer/Reference to the created Secure Channel.
 */
t_MKA_receive_sc* MKA_SECY_CreateReceiveSC(t_MKA_bus bus, t_MKA_sci const* sci);

/**
 * Function to delete a Reception Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sc: Pointer/Reference to the Secure Channel to be deleted
 */
void MKA_SECY_DestroyReceiveSC(t_MKA_bus bus, t_MKA_receive_sc* sc);

/**
 * Function to create a Transmission Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number for the created Secure Association
 * @param[in] next_pn: Next packet number for the created Secure Association
 * @param[in] co: Confidentility offset for the created Secure Association
 * @param[in] sak: Pointer/Reference to the key to be used for the created Secure Association
 * 
 * @return Pointer/Reference to the created Secure Association.
 */
t_MKA_transmit_sa* MKA_SECY_CreateTransmitSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_confidentiality_offset co, void* sak);

/**
 * Function to delete a Transmission Secure Association
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sa: Pointer/Reference to the Secure Association to be deleted
 */
void MKA_SECY_DestroyTransmitSA(t_MKA_bus bus, t_MKA_transmit_sa* sa);

/**
 * Function to create a Transmission Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Association Number for the created Secure Association
 * @param[in] lowest_pn: Lowest packet number for the created Secure Association
 * @param[in] sak: Pointer/Reference to the key to be used for the created Secure Association
 * 
 * @return Pointer/Reference to the created Secure Association.
 */
t_MKA_receive_sa* MKA_SECY_CreateReceiveSA(t_MKA_bus bus, uint8_t an, t_MKA_pn lowest_pn, t_MKA_ssci ssci, void* sak);

/**
 * Function to delete a Reception Secure Association
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sa: Pointer/Reference to the Secure Association to be deleted
 */
void MKA_SECY_DestroyReceiveSA(t_MKA_bus bus, t_MKA_receive_sa* sa);

/**
 * Function to enable a Transmission Secure Association
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sa: Pointer/Reference to the Secure Association to be enabled
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_SECY_TransmitSA_EnableTransmit(t_MKA_bus bus, t_MKA_transmit_sa*sa);

/**
 * Function to enable a Reception Secure Association
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sa: Pointer/Reference to the Secure Association to be enabled
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_SECY_ReceiveSA_EnableReceive(t_MKA_bus bus, t_MKA_receive_sa*sa);

/**
 * Function to update nextPN for a Reception Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sa: Pointer/Reference to the Secure Association to set nextPN
 * @param[in] next_pn: Value for nextPN to be installed in Transmission Secure Association
 */
void MKA_SECY_ReceiveSA_UpdateNextPN(t_MKA_bus bus, t_MKA_receive_sa*sa, t_MKA_pn next_pn);

/**
 * Function to update/retrieve nextPN from a Transmission Secure Channel
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] sa: Pointer/Reference to the Secure Association to update nextPN
 *
 * @return MKA_OK: Operation OK.
 * @return MKA_NOT_OK: An error occurred.
 */
t_MKA_result MKA_SECY_TransmitSA_UpdateNextPN(t_MKA_bus bus, t_MKA_transmit_sa*sa);

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
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc);

#ifdef __cplusplus
}
#endif

#endif
