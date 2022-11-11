/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-timer.cpp
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

/* Description: Unit test template.
 * Author: Your name here
 *
 * Execute the following command to run this test alone, without coverage:
 * $ python waf test --targets=test_name --coverage=no
 *
 * Execute the following command to run ALL tests:
 * $ python waf test
 *
 */
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "ut_helpers.h"
#include "mka_private.h"

uint32_t mka_tick_time_ms = 0U;

struct timer_basic : public ::testing::Test {
    t_mka_timer timer;
    virtual void StartUp(void) {
        mka_tick_time_ms = 0U;
    }
};

struct timer_started : public timer_basic {
    virtual void StartUp(void) {
        timer_basic::StartUp();

        mka_timer_init(&timer);

        mka_tick_time_ms = 1234U;
    }
};

TEST_F(timer_basic, init)
{
    mka_timer_init(&timer);
    ASSERT_FALSE(mka_timer_running(&timer));
}

TEST_F(timer_basic, start)
{
    mka_timer_init(&timer);

    mka_tick_time_ms = 1234U;
    mka_timer_start(&timer, 100U);

    ASSERT_TRUE(mka_timer_running(&timer));
    ASSERT_FALSE(mka_timer_expired(&timer));
}

TEST_F(timer_started, expiry)
{
    mka_timer_start(&timer, 100U);
    ASSERT_FALSE(mka_timer_expired(&timer));

    mka_tick_time_ms += 99;
    ASSERT_FALSE(mka_timer_expired(&timer));

    mka_tick_time_ms += 1;
    ASSERT_TRUE(mka_timer_expired(&timer));

    mka_tick_time_ms += 1;
    ASSERT_TRUE(mka_timer_expired(&timer));

    mka_timer_stop(&timer);
    ASSERT_FALSE(mka_timer_running(&timer));
    ASSERT_FALSE(mka_timer_expired(&timer));
}
