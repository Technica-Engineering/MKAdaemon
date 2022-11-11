/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_l2_private.h
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
******************************************************************************/

/****** Copyright 2021 Technica Engineering ********************************//**
 * @file        mka_l2.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA L2 private interface
 *
 * @{
 */

#ifndef MKA_L2_PRIVATE_H_
#define MKA_L2_PRIVATE_H_

/*******************        Includes        *************************/
#include "mka_private.h"

#ifdef __cplusplus
extern "C" {
#endif

//lint -estring(9058, s_mka_dsa_group) [MISRA 2012 Rule 2.4, advisory] mandatory struct outside of typedef in order to use forward declaration in API to achieve an opaque type

/*******************        Defines           ***********************/

/*******************        Types             ***********************/
struct s_mka_dsa_group;
typedef struct s_mka_dsa_group t_mka_dsa_group;

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/
/**
 * @brief Initialise DSA for given bus.
 * @note Buses that connect to the same switch will result in the same DSA group (hence same link to the switch).
 * @note This implementation assumes that the switch is configured and ready to work in the appropriate DSA mode.
 *
 * @param[in] bus       DSA group corresponding to lower layer directly connected to the switch.
 *
 * @return Assigned DSA group
 */
t_mka_dsa_group *MKA_l2_dsa_init(t_MKA_bus bus);

/**
 * @brief Initialise DSA for a given bus.
 * @note Bus will be simply removed from DSA group. No frames will be received from this point until an init.
 *
 * @param[in] bus       DSA group corresponding to lower layer directly connected to the switch.
 */
void MKA_l2_dsa_deinit(t_MKA_bus bus);

/**
 * @brief Handle reception of a packet in a DSA group, locating MKA bus where packet originated.
 * @note If bus is found, packet content, pointer and length are modified to remove DSA headers.
 *
 * @param[in] group     DSA group corresponding to lower layer directly connected to the switch.
 * @param[inout] packet input: Incoming frame from switch, output: Incoming frame from switch port
 * @param[inout] length input: Incoming frame length from switch, output: Incoming frame length from switch port
 * @param[in] ethertype Protocol number to consider a packet interesting
 * @param[out] bus      MKA bus that matches the port where the packet originated.
 *
 * @return true when packet is originated from a known port and ethertype matches.
 * @return false otherwise. Original packet is never modified with this return code.
 */
bool MKA_l2_dsa_handle_reception(t_mka_dsa_group const*group, uint8_t **packet, uint16_t *length, uint16_t expected_ethertype, t_MKA_bus* bus);

/**
 * @brief Copy a packet to a transmission buffer of size (packet_len+dsa_header) including DSA headers.
 * @note DSA header length can be retrieved with API MKA_l2_dsa_get_bus_header_len.
 *
 * @param[in] bus           MKA bus whose port the frame is going to be transmitted to.
 * @param[out] tx_buffer    Transmission buffer where the frame is to be copied to.
 * @param[in] packet        EAPOL packet to transmit.
 * @param[in] packet_len    Length of the EAPOL packet.
 *
 * @return true if packet was prepared without errors
 * @return false when an unspecified error occurred.
 */
bool MKA_l2_dsa_prepare_transmission(t_MKA_bus bus, uint8_t *tx_buffer, uint8_t const*packet, uint16_t packet_len);

/**
 * @brief Get overhead of DSA header with the configuration of a DSA group.
 *
 * @parm[in] group          DSA group
 *
 * @return DSA header size.
 */
uint16_t MKA_l2_dsa_get_group_header_len(t_mka_dsa_group const*group);

/**
 * @brief Get overhead of DSA header with the configuration of a particular bus.
 *
 * @parm[in] bus            MKA bus
 *
 * @return DSA header size.
 */
uint16_t MKA_l2_dsa_get_bus_header_len(t_MKA_bus bus);

/*******************        Func. definition  ***********************/

#ifdef __cplusplus
}
#endif

#endif /* MKA_L2_PRIVATE_H_ */

/** @} */


