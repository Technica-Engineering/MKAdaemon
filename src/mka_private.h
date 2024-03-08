/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_private.h
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
 * @file        mka_types.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA types abstraction
 *
 * @{
 */

#ifndef MKA_PRIVATE_H_
#define MKA_PRIVATE_H_

/*******************        Includes        *************************/
#include "mka_types.h"
#ifdef MKA_STANDALONE_COMPILATION
# include "mka_daemon_config.h"
#else
# include "mka_config.h"
#endif

#if (MKA_RUNNING_OS == MKA_OS_FREERTOS_LWIP)
#elif (MKA_RUNNING_OS == MKA_OS_LINUX)
#elif (MKA_RUNNING_OS == MKA_OS_AUTOSAR)
#elif (MKA_RUNNING_OS == MKA_OS_MARVELL_SDK)
#elif defined(UNIT_TEST)
#else
# error "Unknown operating system."
#endif

#include "mka.h"
#include "mka_l2.h"
#include "mka_fsm.h"
#include "mka_fifo.h"
#ifdef MKA_STANDALONE_COMPILATION
# include "mka_timers_event.h"
# include <time.h>
#else
# include "mka_timers.h"
#endif
#include "mka_kay.h"
#include "mka_logon.h"
#include "mka_cp.h"
#include "mka_secy.h"
#include "mka_crypto.h"

//lint -save
//lint -e9026 [MISRA 2012 Directive 4.9, advisory] Function-like macros for more readable code
//lint -e9024 [MISRA 2012 Rule 20.10, advisory] #/## operator is used in a controlled way to get more readable code when logging

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/
/*------------- Logging system -------------------
 * Usage examples:
 *  MKA_LOG_ERROR("error occured, bus: %i", bus_number);
 *  MKA_LOG_WARNING("message with arguments: %s", argument0);
 *  MKA_LOG_INFO("information message");
 *  MKA_LOG_DEBUG0("debug message with verbosity level 0 (less verbose)");
 *  MKA_LOG_DEBUG1("debug message with verbosity level 1 (more verbose)");
 *  MKA_LOG_DEBUG2("debug message with verbosity level 2 (more verbose)");
 *  MKA_LOG_DEBUG3("debug message with verbosity level 3 (more verbose)");
 */

#define MKA_LOGGING_ENABLED (MKA_CFG_LOGGING_LEVEL > MKA_LOGLEVEL_DISABLED)

#if defined(MKA_STANDALONE_COMPILATION)
// Dynamic logging configuration
# define MKA_LOG_FILTER_DYNAMIC(level, verbosity, action) /*lint -save */ \
    /*lint -e506 [MISRA 2012 Rule 2.1, required] constant-value boolean mandatory in do..while(0) expression */ \
    /*lint -e717 do..while(0) packs whole block in a single C sentence */ \
    do {									\
        if ((MKA_ACTIVE_LOG_LEVEL >= (level)) && (((level) != MKA_LOGLEVEL_DEBUG) || \
                ((verbosity) <= MKA_ACTIVE_LOG_VERBOSITY))) { \
            action; \
        } \
    } while(false) /*lint -restore */
#else
// Static logging configuration
# define MKA_LOG_FILTER_DYNAMIC(level, verbosity, action) /*lint -save */ \
    /*lint -e506 [MISRA 2012 Rule 2.1, required] constant-value boolean mandatory in do..while(0) expression */ \
    /*lint -e717 do..while(0) packs whole block in a single C sentence */ \
    do {					\
        action;\
    } while(false) /*lint -restore */
#endif

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG
# define MKA_LOG_DEBUG0(...)       MKA_LOG_FILTER_DYNAMIC(MKA_LOGLEVEL_DEBUG, 0U, \
                                        MKA_LOG(MKA_LOGLEVEL_DEBUG, ## __VA_ARGS__) )
# if MKA_CFG_VERBOSITY >= 1U // Verbosity level 1
#  define MKA_LOG_DEBUG1(...)       MKA_LOG_FILTER_DYNAMIC(MKA_LOGLEVEL_DEBUG, 1U, \
                                        MKA_LOG(MKA_LOGLEVEL_DEBUG, ## __VA_ARGS__) )
# else
#  define MKA_LOG_DEBUG1(...)       (void)1 /* sentence to be optimised by compiler */
# endif
# if MKA_CFG_VERBOSITY >= 2U // Verbosity level 2
#  define MKA_LOG_DEBUG2(...)       MKA_LOG_FILTER_DYNAMIC(MKA_LOGLEVEL_DEBUG, 2U, \
                                        MKA_LOG(MKA_LOGLEVEL_DEBUG, ## __VA_ARGS__) )
# else
#  define MKA_LOG_DEBUG2(...)       (void)1 /* sentence to be optimised by compiler */
# endif
# if MKA_CFG_VERBOSITY >= 3U // Verbosity level 3
#  define MKA_LOG_DEBUG3(...)       MKA_LOG_FILTER_DYNAMIC(MKA_LOGLEVEL_DEBUG, 3U, \
                                        MKA_LOG(MKA_LOGLEVEL_DEBUG, ## __VA_ARGS__) )
# else
#  define MKA_LOG_DEBUG3(...)       (void)1 /* sentence to be optimised by compiler */
# endif
#else
# define MKA_LOG_DEBUG0(...)        (void)1 /* sentence to be optimised by compiler */
# define MKA_LOG_DEBUG1(...)        (void)1 /* sentence to be optimised by compiler */
# define MKA_LOG_DEBUG2(...)        (void)1 /* sentence to be optimised by compiler */
# define MKA_LOG_DEBUG3(...)        (void)1 /* sentence to be optimised by compiler */
#endif

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_INFO
# define MKA_LOG_INFO(...)          MKA_LOG_FILTER_DYNAMIC(MKA_LOGLEVEL_INFO, 0U, \
                                        MKA_LOG(MKA_LOGLEVEL_INFO, ## __VA_ARGS__) )
#else
# define MKA_LOG_INFO(...)          (void)1 /* sentence to be optimised by compiler */
#endif

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_WARNING
# define MKA_LOG_WARNING(...)       MKA_LOG_FILTER_DYNAMIC(MKA_LOGLEVEL_WARNING, 0U, \
                                        MKA_LOG(MKA_LOGLEVEL_WARNING, ## __VA_ARGS__) )
#else
# define MKA_LOG_WARNING(...)       (void)1 /* sentence to be optimised by compiler */
#endif

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_ERROR
# define MKA_LOG_ERROR(...)         MKA_LOG_FILTER_DYNAMIC(MKA_LOGLEVEL_ERROR, 0U, \
                                        MKA_LOG(MKA_LOGLEVEL_ERROR, ## __VA_ARGS__) )
#else
# define MKA_LOG_ERROR(...)         (void)1 /* sentence to be optimised by compiler */
#endif

#ifdef MKA_CFG_ASSERT_ACTION
# define MKA_ASSERT(condition, format, ...) /*lint -save */ \
    /*lint -e506 [MISRA 2012 Rule 2.1, required] constant-value boolean mandatory in do..while(0) expression */ \
    /*lint -e717 do..while(0) packs whole block in a single C sentence */ \
    do { \
        if (!(condition)) { \
            MKA_LOG_ERROR("ASSERT FAIL: " format, ## __VA_ARGS__); \
            MKA_CFG_ASSERT_ACTION(); \
        } \
    } while (false) /*lint -restore */
#else
# define MKA_ASSERT(condition, ...) (void)(condition) /* evaluate anyway, compiler shall optimise when possible */
#endif

# define MKA_LOG(level, fmt, ...) \
    MKA_log_from_func(level, __func__, __LINE__, fmt "\r\n", ## __VA_ARGS__)

/*------------- Event system -------------------
 * Usage examples:
 *  MKA_EVENT(MKA_EVENT_INIT); -- defined in mka_types.h
 *  MKA_BUS_EVENT(bus_number, MKA_EVENT_LINKUP);
 */
#if MKA_CFG_LOGGING_LEVEL < MKA_LOGLEVEL_DEBUG
# define MKA_BUS_EVENT(bus_id, event)   MKA_CFG_EVENT_ACTION(bus_id, event)
# define MKA_EVENT(event)               MKA_CFG_EVENT_ACTION(MKA_BUS_NONE, event)
#else
# define MKA_BUS_EVENT(bus_id, event) /*lint -save */ \
    /*lint -e506 [MISRA 2012 Rule 2.1, required] constant-value boolean mandatory in do..while(0) expression */ \
    /*lint -e717 do..while(0) packs whole block in a single C sentence */ \
    do { \
        MKA_LOG_DEBUG0("Event [" #event "] on bus %i", (bus_id)); \
        MKA_CFG_EVENT_ACTION(bus_id, event); \
    } while(false) /*lint -restore */

# define MKA_EVENT(event) /*lint -save */ \
    /*lint -e506 [MISRA 2012 Rule 2.1, required] constant-value boolean mandatory in do..while(0) expression */ \
    /*lint -e717 do..while(0) packs whole block in a single C sentence */ \
    do { \
        MKA_LOG_DEBUG0("Event [" #event "]"); \
        MKA_CFG_EVENT_ACTION(MKA_BUS_NONE, event); \
    } while(false) /*lint -restore */
#endif


#ifndef MIN
# define MIN(a, b)              ( ((a) > (b)) ? (b) : (a) )
#endif

#ifndef MAX
# define MAX(a, b)              ( ((a) <= (b)) ? (b) : (a) )
#endif

#define MKA_ALIGN_TO_32BIT(x)   (((x) + 3U) & 0xFFFFFFFCUL)

#define MKA_ARRAY_SIZE(x)       ((sizeof(x)/sizeof((x)[0])))

#ifndef MKA_NUM_BUSES_CONFIGURED
# define MKA_NUM_BUSES_CONFIGURED       MKA_NUM_BUSES
#endif

#ifndef MKA_MKPDU_VERSION_ID
# define MKA_MKPDU_VERSION_ID       3U
#endif

#ifndef MKA_ALLOW_OTHER_VERSIONS
# define MKA_ALLOW_OTHER_VERSIONS   0
#endif


/*******************        Types             ***********************/
typedef uint8_t t_MKA_log_level;

/*******************        Variables         ***********************/
extern t_MKA_global_config const* MKA_active_global_config;
extern t_MKA_bus_config const* MKA_active_buses_config;

/*******************        Func. prototypes  ***********************/
void MKA_log_from_func(uint8_t const level, const char *const function, uint32_t const line, const char *const fmt, ...);
#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG
char* MKA_MAC_to_string(uint8_t const*const addr);
#endif
#ifdef MKA_STANDALONE_COMPILATION
extern t_MKA_config const* mka_config_load(char const* filename);
extern void mka_config_free(t_MKA_config *config);
extern void mka_main_loop_wakeup(void);
extern void mka_main_global_mutex_lock(void);
extern void mka_main_global_mutex_unlock(void);
extern void mka_daemon_exit(sint_t exit_code);
bool mka_AddSleepTime(struct timespec* max_wait);
/// Start physical link monitor
extern void mka_link_monitor_start(void);
/// Stop physical link monitor
extern void mka_link_monitor_stop(void);
/// Update status of physical links
extern void mka_link_monitor_update(void);
#endif
#if (MKA_RUNNING_OS == MKA_OS_MARVELL_SDK)
uint32_t MKA_HandleDSAPacket(uint32_t buffer_index, uint16_t length, uint8_t* packet_buffer);
void MKA_MarvellConfig(uint32_t transmit_queue);
#endif

/*******************        Func. definition  ***********************/

static inline bool MKA_sci_equal(t_MKA_sci const* a, t_MKA_sci const* b)
{
    return 0 == memcmp(a, b, sizeof(t_MKA_sci));
}

static inline bool MKA_is_mi_null(uint8_t const* a)
{
    uint8_t sum = 0U;
    for(uint8_t i=0U; i<MKA_MI_LENGTH; ++i) {
        sum |= a[i];
    }
    return 0U == sum;
}

static inline bool MKA_mi_equal(uint8_t const* a, uint8_t const* b)
{
    return 0 == memcmp(a, b, MKA_MI_LENGTH);
}

static inline bool MKA_ki_equal(t_MKA_ki const* a, t_MKA_ki const* b)
{
    return 0 == memcmp(a, b, sizeof(t_MKA_ki));
}

#ifdef __cplusplus
}
#endif

//lint -restore

#endif /* MKA_PRIVATE_H_ */


/** @} */
