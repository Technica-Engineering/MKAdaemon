/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_kay.h
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
 * @file        mka_kay.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA Key Access 
 *
 * @{
 */

#ifndef MKA_KAY_H_
#define MKA_KAY_H_

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
 * Initialise KAY for a given bus.
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
void MKA_KAY_Init(t_MKA_bus bus);

/**
 * Cyclic reception tasks for a given bus.
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
void MKA_KAY_MainFunctionReception(t_MKA_bus bus);

/**
 * Cyclic timers tasks for a given bus.
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
void MKA_KAY_MainFunctionTimers(t_MKA_bus bus);

/**
 * Cyclic timers tasks for a given bus.
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
void MKA_KAY_MainFunctionTransmission(t_MKA_bus bus);

/**
 * Set whether the given bus is enabled
 * @remark Reentrant and thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] enable Enable/Disable functionality
 */
void MKA_KAY_SetEnable(t_MKA_bus bus, bool enable);

/**
 * Get whether the given bus is enabled
 * @remark Reentrant and thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @return true  MKA/MACSEC enabled in given bus
 * @return false MKA/MACSEC disabled in given bus
 */
bool MKA_KAY_GetEnable(t_MKA_bus bus);

/**
 * Create an MKA participant in the given bus
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] ckn CA key name
 * @param[in] cak CA key
 * @param[in] kek KEK key derived from CAK
 * @param[in] ick ICK key derived from CAK
 * @param[in] authdata Authorisation data
 * @param[in] life CAK key life time
 * @return true  Participant creation success
 * @return false Participant creation error
 */
bool MKA_KAY_CreateMKA(t_MKA_bus bus, t_MKA_ckn const*ckn, t_MKA_key const*cak, t_MKA_key const*kek,
                                t_MKA_key const*ick, void const*authdata, uint32_t life);
/**
 * Delete the MKA participant in the given bus
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
void MKA_KAY_DeleteMKA(t_MKA_bus bus);

/**
 * Make the participant active in the bus even without peers
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
void MKA_KAY_Participate(t_MKA_bus bus, bool enable);

/**
 * Create the necessary security associations for the given key identifier
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] ki Key identifier
 */
void MKA_KAY_CreateSAs(t_MKA_bus bus, t_MKA_ki const* ki);

/**
 * Enable reception via the given key identifier
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] ki Key identifier
 */
void MKA_KAY_EnableReceiveSAs(t_MKA_bus bus, t_MKA_ki const* ki);

/**
 * Enable transmission via the given key identifier
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] ki Key identifier
 */
void MKA_KAY_EnableTransmitSA(t_MKA_bus bus, t_MKA_ki const* ki);

/**
 * Delete security associations for the given key identifier
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[in] ki Key identifier
 */
void MKA_KAY_DeleteSAs(t_MKA_bus bus, t_MKA_ki const* ki);

/**
 * Signal new info to KAY in order to generate a MKPDU the next tick
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
void MKA_KAY_SignalNewInfo(t_MKA_bus bus);

/**
 * Get current protectFrames variable value
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
bool MKA_KAY_GetProtectFrames(t_MKA_bus bus);

/**
 * Get current validateFrames variable value
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
t_MKA_validate_frames MKA_KAY_GetValidateFrames(t_MKA_bus bus);

/**
 * Get current replayProtect variable value
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
bool MKA_KAY_GetReplayProtect(t_MKA_bus bus);

/**
 * Get current replayProtectWindow variable value
 * @remark Non reentrant, non thread safe.
 * 
 * @param[in] bus MKA bus instance identifier
 */
uint32_t MKA_KAY_GetReplayWindow(t_MKA_bus bus);

/*lint -sem(MKA_KAY_GetBusInfo, 2p, 1n<MKA_NUM_BUSES && 2p>=1) */
/**
 * Returns the MKA status for a given bus.
 * @remark Non reentrant, non thread safe.
 *
 * @param[in] bus Bus number
 * @param[out] info Bus status information
 *
 * @return MKA_OK       Status update to incoming structure.
 * @return MKA_NOT_OK   Status update error; invalid bus.
 */
t_MKA_result MKA_KAY_GetBusInfo(t_MKA_bus bus, t_MKA_bus_info* info);

/*******************        Func. definition  ***********************/


#ifdef __cplusplus
}
#endif

#endif /* MKA_KAY_H_ */

/** @} */


