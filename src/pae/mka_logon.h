/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_logon.h
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
 * @file        mka_logon.h
 * @version     1.0.0
 * @author      Ferran Pedrera
 * @brief       PAE Logon definition (802.1x 2020)
 *
 * @{
 */

#ifndef MKA_LOGON_H_
#define MKA_LOGON_H_

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
 * Initialises LOGON module.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_LOGON_Init(t_MKA_bus bus);

/**
 * Runs LOGON module periodic functionality.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_LOGON_MainFunction(t_MKA_bus bus);

/**
 * Public API to modify LOGON enable flag.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in logon
 */
void MKA_LOGON_SetLogonEnabled(t_MKA_bus bus, bool status);

/**
 * Public API to modify LOGON mka.enabled interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in portEnabled
 */
void MKA_LOGON_SetKayEnabled(t_MKA_bus bus, bool status);

/**
 * Public API to notify LOGON module that MKA has been deleted.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_LOGON_SignalDeletedMKA(t_MKA_bus bus);

/**
 * Public API to notify LOGON type of connection.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in portEnabled
 */
void MKA_LOGON_SetKayConnectMode(t_MKA_bus bus, t_MKA_connect_mode mode);

/**
 * Public API to modify LOGON portEnabled interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in portEnabled
 */
void MKA_LOGON_SetPortEnabled(t_MKA_bus bus, bool status);

/**
 * Public API to modify LOGON activate parameter.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] activate: Value to write in activate parameter
 */
void MKA_LOGON_SetActivate(t_MKA_bus bus, t_MKA_activate activate);

#ifdef __cplusplus
}
#endif

#endif // MKA_LOGON_H_

