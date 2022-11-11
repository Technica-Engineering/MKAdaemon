/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_daemon_config.h
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
 * @file        mka_config.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA configuration
 *
 * @{
 */

#ifndef MKA_CONFIG_H_
#define MKA_CONFIG_H_

/*******************        Includes        *************************/
#include <stdlib.h> // exit
#include <stdio.h>
#include "main.h"

#ifdef ENABLE_DBUS
#include "dbus_event_action.h"
#endif

//lint -save
//lint -e9026 [MISRA 2012 Directive 4.9, advisory] Function-like macros for easier configuration

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/
#define MKA_CRITICAL_ENTER()                mka_main_global_mutex_lock()
#define MKA_CRITICAL_LEAVE()                mka_main_global_mutex_unlock()

#define MKA_RUNNING_OS                      MKA_OS_LINUX

/* ---------------------------- bus configuration ---------------------------*/
#define MKA_NUM_BUSES                       20U

#define MKA_NUM_BUSES_CONFIGURED            mka_num_buses_configured
extern uint32_t mka_num_buses_configured;       // from config file

/* --------------------- logging / assert configuration ---------------------*/
extern uint8_t mka_active_log_level;            // from config file
#ifndef MKA_ACTIVE_LOG_LEVEL
#define MKA_ACTIVE_LOG_LEVEL                mka_active_log_level
#endif

extern uint8_t mka_active_log_verbosity;        // from config file
#ifndef MKA_ACTIVE_LOG_VERBOSITY
#define MKA_ACTIVE_LOG_VERBOSITY            mka_active_log_verbosity
#endif

/* Action to perform after an assert is triggered */
#ifdef UNIT_TEST
extern void mock_assertion_action(void);
# define MKA_CFG_ASSERT_ACTION()            mock_assertion_action()
#else
# define MKA_CFG_ASSERT_ACTION()            mka_daemon_exit(-1)
#endif

#define MKA_CFG_LOG_TO_BUFFER               MKA_OFF

/* Action to perform to log, TODO: syslog? file? */
#ifdef UNIT_TEST
extern void mock_print(char const* text, unsigned long length);
#define MKA_CFG_LOG_ACTION(text, length)    mock_print(text, length)
#else
# define MKA_CFG_LOG_ACTION(text, length)   write_log(text, length)
#endif

/* Action to perform on MKA events */
#ifdef ENABLE_DBUS
#define MKA_CFG_EVENT_ACTION(bus, event)    dbus_notify_event(bus,event)
#else
#define MKA_CFG_EVENT_ACTION(bus, event)    (void)1
#endif

/* MKA compile-time logging level */
#define MKA_CFG_LOGGING_LEVEL               MKA_LOGLEVEL_DEBUG

/* MKA logging verbosity level (only applicable for debug logging level) */
#define MKA_CFG_VERBOSITY                   3U

/* MKA log format in stack */
#define MKA_LOG_FORMAT_STACK                MKA_OFF

/* MKA log line max length */
#define MKA_LOG_MAXLENGTH                   2048U

/** Maximum number of elements in MKA Hello time rampup arrays
 */
#define MKA_MAX_RAMPUP_ELEMS         100U

// Size of history of SAK-nonce pairs
#define MKA_KS_HISTORY_SIZE                 4U // hardcoded

// Generate random SAK instead of deriving it from CAK & MI's
#define MKA_GENERATE_RANDOM_SAK             MKA_OFF

#define MKA_TRANSMIT_ON_PEER_LEARNT         MKA_ON

/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

t_MKA_result MKA_RetrieveCAKCKN(t_MKA_bus bus, t_MKA_key * const cak, t_MKA_ckn * const ckn);
t_MKA_result MKA_RetrieveKEK(t_MKA_bus bus, t_MKA_key * const kek);
t_MKA_result MKA_RetrieveICK(t_MKA_bus bus, t_MKA_key * const ick);


/*******************        Func. definition  ***********************/


#ifdef __cplusplus
}
#endif

#endif /* MKA_CONFIG_H_ */

//lint -restore

/** @} */
