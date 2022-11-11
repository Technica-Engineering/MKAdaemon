/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_cp.h
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
 * @file        mka_cp.h
 * @version     1.0.0
 * @author      Ferran Pedrera
 * @brief       PAE Controller Port (CP) definition (802.1x 2020 Chapter 12)
 *
 * @{
 */

#ifndef MKA_CP_H_
#define MKA_CP_H_

/*******************        Includes        *************************/

#include "mka_private.h"
#include "mka_kay.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

/**
 * Initialises CP module FSM.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_Init(t_MKA_bus bus);

/**
 * Runs CP module FSM until reaching stable state.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_MainFunction(t_MKA_bus bus);

/**
 * Public API to modify CP portEnabled interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in portEnabled
 */
void MKA_CP_SetPortEnabled(t_MKA_bus bus, bool status);

/**
 * Public API to modify CP cipherSuite interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] cipher_suite: Value to write in cipherSuite
 */
void MKA_CP_SetCipherSuite(t_MKA_bus bus, uint64_t cipher_suite);

/**
 * Public API to modify CP cipherOffset interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] cipher_offset: Value to write in cipherOffset
 */
void MKA_CP_SetCipherOffset(t_MKA_bus bus, t_MKA_confidentiality_offset cipher_offset);

/**
 * Public API to modify CP distributedKI interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] ki: Value to write in distributedKI
 */
void MKA_CP_SetDistributedKI(t_MKA_bus bus, const t_MKA_ki * ki);

/**
 * Public API to modify CP distributedAN interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] an: Value to write in distributedAN
 */
void MKA_CP_SetDistributedAN(t_MKA_bus bus, uint8_t an);

/**
 * Public API to modify CP usingReceiveSAs interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in usingReceiveSAs
 */
void MKA_CP_SetUsingReceiveSAs(t_MKA_bus bus, bool status);

/**
 * Public API to modify CP electedSelf interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in electedSelf
 */
void MKA_CP_SetElectedSelf(t_MKA_bus bus, bool status);

/**
 * Public API to modify CP allReceiving interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in allReceiving
 */
void MKA_CP_SetAllReceiving(t_MKA_bus bus, bool status);

/**
 * Public API to modify CP usingTransmitSA interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in usingTransmitSA
 */
void MKA_CP_SetUsingTransmitSA(t_MKA_bus bus, bool status);

/**
 * Public API to modify CP serverTransmitting interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @param[in] status: Value to write in serverTransmitting
 */
void MKA_CP_SetServerTransmitting(t_MKA_bus bus, bool status);

/**
 * Public API to signal a change in CP chgdServer interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_SignalChgdServer(t_MKA_bus bus);

/**
 * Public API to signal a change in CP newSAK interface.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_SignalNewSAK(t_MKA_bus bus);

/**
 * Public API to set CP connect interface to PENDING.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_ConnectPending(t_MKA_bus bus);

/**
 * Public API to set CP connect interface to UNAUTHENTICATED.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_ConnectUnauthenticated(t_MKA_bus bus);

/**
 * Public API to set CP connect interface to AUTHENTICATED.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_ConnectAuthenticated(t_MKA_bus bus);

/**
 * Public API to set CP connect interface to SECURE.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 */
void MKA_CP_ConnectSecure(t_MKA_bus bus);

/**
 * Public getter for current value of ProtectFrames.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @return true  Protect Frames enabled
 * @return false Protect Frames disabled
 */
bool MKA_CP_GetProtectFrames(t_MKA_bus bus);

/**
 * Public getter for current value of ValidateFrames.
 * reentrancy: Reentrant.
 * 
 * @param[in] bus: MKA bus instance identifier
 * @return Validate frames configuration
 */
t_MKA_validate_frames MKA_CP_GetValidateFrames(t_MKA_bus bus);

/**
 * Get old security association parameters
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[out] oki Old key identifier
 * @param[out] oan Old key association number
 * @param[out] otx Old key transmitting
 * @param[out] orx Old key receiving
 */
void MKA_CP_GetOldSA(t_MKA_bus bus, t_MKA_ki const**oki, uint8_t *oan, bool *otx, bool *orx);

/**
 * Get latest security association parameters
 * 
 * @param[in] bus MKA bus instance identifier
 * @param[out] lki Latest key identifier
 * @param[out] lan Latest key association number
 * @param[out] ltx Latest key transmitting
 * @param[out] lrx Latest key receiving
 */
void MKA_CP_GetLatestSA(t_MKA_bus bus, t_MKA_ki const**lki, uint8_t *lan, bool *ltx, bool *lrx);


#ifdef __cplusplus
}
#endif

#endif /* MKA_CP_H_ */

/** @} */
