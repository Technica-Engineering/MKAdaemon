/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_timers_event.c
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
 * @file        mka_timers.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA types abstraction for linux event-based mechanism
 *
 * @{
 */

/*******************        Includes        *************************/
#include "mka_private.h"

/*******************        Defines           ***********************/
#define MKA_TIMER_SLEEP_MAX_MS          500U

/*******************        Types             ***********************/
struct t_mka_slot_struct {
    bool enable;
    uint32_t expiry;
    bool waiting_reload;
};

static t_mka_slot timer_slots[MKA_TIMER_NUM] = {0};

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/
static t_mka_slot* get_slot(t_mka_timer* const timer);

/*******************        Func. definition  ***********************/
static t_mka_slot* get_slot(t_mka_timer* const timer)
{
    for(uint_t i=0U; (NULL == timer->ref) && (i<MKA_TIMER_NUM); ++i) {
        if (!timer_slots[i].enable) {
            timer_slots[i].enable = true;
            timer_slots[i].expiry = MKA_TIMER_MAX;

            timer->ref = &timer_slots[i];
        }
    }

    MKA_ASSERT(NULL != timer->ref, "Too many timers in use!");

    return timer->ref;
}

uint32_t mka_timer_maxsleep(void)
{
    uint32_t sleep_time = MKA_TIMER_SLEEP_MAX_MS;

    for(uint_t i=0U; i<MKA_TIMER_NUM; ++i) {
        t_mka_slot* slot = &timer_slots[i];
        if (slot->enable && (!slot->waiting_reload) && (slot->expiry < MKA_TIMER_MAX)) {
            uint32_t const remaining = (slot->expiry >= mka_tick_time_ms) ?
                                (slot->expiry - mka_tick_time_ms) : 0U;
            slot->waiting_reload = (bool)(0U == remaining);
            sleep_time = MIN(remaining, sleep_time);
        }
    }

    return sleep_time;
}


void mka_timer_init(t_mka_timer* const timer)
{
    t_mka_slot*const slot = get_slot(timer);
    slot->expiry = MKA_TIMER_MAX;
    slot->waiting_reload = false;
}

void mka_timer_start(t_mka_timer* const timer, uint32_t how_long_ms)
{
    t_mka_slot*const slot = get_slot(timer);
    slot->expiry = mka_tick_time_ms + how_long_ms;
    slot->waiting_reload = false;
}

void mka_timer_extend(t_mka_timer* const timer, uint32_t how_long_ms)
{
    t_mka_slot*const slot = get_slot(timer);
    slot->expiry += how_long_ms;
    slot->waiting_reload = false;
}

void mka_timer_stop(t_mka_timer* const timer)
{
    t_mka_slot*const slot = get_slot(timer);
    slot->expiry = MKA_TIMER_MAX;
    slot->waiting_reload = false;
}

bool mka_timer_running(t_mka_timer const* const timer)
{
    MKA_ASSERT(NULL != timer->ref, "Attempt to call a getter on a non-initialised timer.");
    return (MKA_TIMER_MAX > timer->ref->expiry);
}

bool mka_timer_expired(t_mka_timer const* const timer)
{
    MKA_ASSERT(NULL != timer->ref, "Attempt to call a getter on a non-initialised timer.");
    return (mka_tick_time_ms >= timer->ref->expiry);
}

/*******************        Func. definition  ***********************/

/** @} */




