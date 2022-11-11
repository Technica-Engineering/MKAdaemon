/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_l2.h
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

/*****************************************************************************
 * @file        mka_l2.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA layer 2 abstraction
 *
 * @{
 */

#ifndef MKA_L2_H_
#define MKA_L2_H_

/*******************        Includes        *************************/
#include "mka_private.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/
/* This function initialises layer 2 module for the given bus */
t_MKA_result MKA_l2_init(t_MKA_bus bus, uint16_t protocol);

/* Function to deinitialise layer 2 module for the given bus */
void MKA_l2_deinit(t_MKA_bus bus);

/* Function to transmit layer 2 packet to the given bus */
t_MKA_result MKA_l2_transmit(t_MKA_bus bus, uint8_t const*packet, uint32_t len);

/* Function to receive layer 2 packet from the given bus (NOTE: parameter len is bidirectional) */
t_MKA_result MKA_l2_receive(t_MKA_bus bus, uint8_t *packet, uint32_t *len);

/* Function to obtain adapter's local MAC address */
t_MKA_result MKA_l2_getLocalAddr(t_MKA_bus bus, uint8_t *addr);

/*******************        Func. definition  ***********************/
static inline bool MKA_l2_is_individual_addr(uint8_t const*const addr)
{
    /*lint -e{1960} [MISRA C++ 2008 Required Rule 5-0-15] pointer is presumed to cointain a MAC address */
    return ((addr[0U] & 1U) == 0U);
}

#ifdef __cplusplus
}
#endif

#endif /* MKA_L2_H_ */

/** @} */

