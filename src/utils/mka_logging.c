/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_logging.c
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
 * @file        mka_logging.c
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA types abstraction
 *
 * @{
 */

/*******************        Includes        *************************/
#include "mka_private.h"

#include <stdio.h> // snprintf
#include <stdarg.h>

//lint -estring(586, snprintf, vsnprintf) Functions necessary for string formatting.
//lint -estring(586, va_start, va_end) Macros necessary for variable argument handling.

/*******************        Defines           ***********************/
#define LEVEL_STR_LENGTH    6U
#define LINE_STR_LENGTH     8U
#define FUNC_STR_MAXLENGTH  64U
#define LEVELS_VALID        MKA_LOGLEVEL_DEBUG
#define LEVELS_TOTAL        (LEVELS_VALID+1U)

#if MKA_LOG_MAXLENGTH < (LEVEL_STR_LENGTH+LINE_STR_LENGTH+FUNC_STR_MAXLENGTH+64U)
# error "MKA_LOG_MAXLENGTH configured too low!"
#endif

#if MKA_CFG_LOG_TO_BUFFER == MKA_ON
# ifdef MKA_CFG_LOG_ACTION
#  error "Conflicting options MKA_CFG_LOG_TO_BUFFER and MKA_CFG_LOG_ACTION"
# endif
# define MKA_CFG_LOG_ACTION(text, length)   (void)length
#endif

/*******************        Types             ***********************/

/*******************        Variables         ***********************/
#if MKA_CFG_LOG_TO_BUFFER == MKA_ON
char mka_debug_buffer[MKA_CFG_LOG_LINE_COUNT][MKA_LOG_MAXLENGTH] = {{'\0'}};
uint32_t mka_debug_buffer_idx = 0U;
#endif

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/
#if MKA_LOGGING_ENABLED
void MKA_log_from_func(uint8_t const level, const char *const function,
        uint32_t const line, const char *const fmt, ...)
{
    va_list args;
    static const char level_str[LEVELS_TOTAL][LEVEL_STR_LENGTH] = {
        //lint -e{786} string cocatenation preferrable to trigraph interpretation
        //lint -e{784} '\0' character is not part of the string, this is expected
        "?" "?" "?" "  |", "ERROR|", "WARN |", "INFO |", "DEBUG|",
    };
#if MKA_CFG_LOG_TO_BUFFER == MKA_OFF
 #if MKA_LOG_FORMAT_STACK == MKA_OFF
    static
 #endif
    char format_buffer[MKA_LOG_MAXLENGTH];
#else
    char*const format_buffer = &mka_debug_buffer[mka_debug_buffer_idx][0];
    mka_debug_buffer_idx = (mka_debug_buffer_idx+1U) % MKA_CFG_LOG_LINE_COUNT;
#endif
    uint32_t ptr;
    uint_t line_uint = (uint_t)line;

    /* Append level string */
    (void)os_memcpy(format_buffer, level_str[MIN(level, LEVELS_VALID)], LEVEL_STR_LENGTH);
    ptr = LEVEL_STR_LENGTH;

    /* Append function line */
    ptr += (uint32_t)snprintf(&format_buffer[ptr], LINE_STR_LENGTH, "%6u|", line_uint);

    /* Append function name */
    ptr += (uint32_t)snprintf(&format_buffer[ptr], FUNC_STR_MAXLENGTH, "%s|", function);

    /* Append log text */
    uint32_t const remaining = (MKA_LOG_MAXLENGTH - 1U) - ptr;
    va_start(args, fmt);
    ptr += (uint32_t)vsnprintf(&format_buffer[ptr], remaining, fmt, args);
    va_end(args); //lint !e950 false positive

    MKA_CFG_LOG_ACTION(format_buffer, ptr);
}
#endif /* MKA_LOGGING_ENABLED */

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG
char* MKA_MAC_to_string(uint8_t const*const addr)
{
    static char repr[2U][18U] = {{'\0'}};
    static uint8_t active = 0U;
    active = (active + 1U) & 1U;
    (void)snprintf(&repr[active][0U], 18U, "%02X:%02X:%02X:%02X:%02X:%02X",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return repr[active];
}
#endif


/** @} */

