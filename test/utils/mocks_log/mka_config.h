/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_config.h
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
#include "mka_private.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------ UNIT TEST ------------------------ */
/*******************        Defines           ***********************/
/* Action to perform after an assert is triggered */
extern void mock_assertion_action(void);
#define MKA_CFG_ASSERT_ACTION()             mock_assertion_action()

/* Action to perform to log */
#ifndef MKA_CFG_LOG_TO_BUFFER
# define MKA_CFG_LOG_TO_BUFFER               MKA_OFF
#endif

#define MKA_NUM_BUSES                       1U

#if MKA_CFG_LOG_TO_BUFFER == MKA_OFF
/* Action to perform to log */
extern void mock_print(char const* text, unsigned long length);
#define MKA_CFG_LOG_ACTION(text, length)    mock_print(text, length)
#else
# define MKA_CFG_LOG_LINE_COUNT             32U
#endif

extern void mock_event(t_MKA_bus bus, t_MKA_event event);
/* Action to perform on MKA events */
#define MKA_CFG_EVENT_ACTION(bus, event)    mock_event(bus, event)

/* MKA compile-time logging level */
//#define MKA_CFG_LOGGING_LEVEL               MKA_LOGLEVEL_DEBUG

/* MKA logging verbosity level (only applicable for debug logging level) */
#ifndef MKA_CFG_VERBOSITY
# define MKA_CFG_VERBOSITY                  2U
#endif

/* MKA log format in stack 
 *   1U - allocated in stack
 *   0U - allocated as global function
 */
#define MKA_LOG_FORMAT_STACK                1U

/* MKA log line max length */
#define MKA_LOG_MAXLENGTH                   256

/** Maximum number of elements in MKA Hello time rampup arrays
 */
#define MKA_MAX_RAMPUP_ELEMS         100U

#define MKA_SAK_LIST_SIZE                   4U

/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/


#ifdef __cplusplus
}
#endif

#endif /* MKA_CONFIG_H_ */

/** @} */

