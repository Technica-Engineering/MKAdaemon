/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-log-buffer.cpp
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

extern "C" void mock_assertion_action(void) { }
extern "C" void mock_event(t_MKA_bus bus, t_MKA_event event) { }

struct logging : public ::testing::Test {
    virtual void SetUp(void)
    {
        mka_debug_buffer_idx = 0U;
        memset(mka_debug_buffer, 0, sizeof(mka_debug_buffer));
    }
    virtual void TearDown(void)
    {
        ASSERT_LT(mka_debug_buffer_idx, MKA_CFG_LOG_LINE_COUNT) << "mka_debug_buffer_id overflow";
    }
};
struct events : public logging {};

TEST_F(logging, info_message)
{
    MKA_LOG_INFO("Test logging message");
    EXPECT_EQ(1U, mka_debug_buffer_idx);
    EXPECT_THAT(mka_debug_buffer[0U], LoggingMessage("INFO |xxxxxx|TestBody|Test logging message\r\n"));
    EXPECT_THAT(mka_debug_buffer[1U], LoggingMessage(""));
}

TEST_F(logging, info_multiple_messages)
{
    MKA_LOG_INFO("First message");
    MKA_LOG_INFO("Second message");
    EXPECT_EQ(2U, mka_debug_buffer_idx);
    EXPECT_THAT(mka_debug_buffer[0U], LoggingMessage("INFO |xxxxxx|TestBody|First message\r\n"));
    EXPECT_THAT(mka_debug_buffer[1U], LoggingMessage("INFO |xxxxxx|TestBody|Second message\r\n"));
    EXPECT_THAT(mka_debug_buffer[2U], LoggingMessage(""));
}

TEST_F(logging, info_wrap_around)
{
    // MKA_CFG_LOG_LINE_COUNT == 32U
    for(int i=0; i<(32+2); ++i) {
        MKA_LOG_INFO("This is log message number %d", i);
    }

    EXPECT_EQ(2U, mka_debug_buffer_idx);
    EXPECT_THAT(mka_debug_buffer[0U], LoggingMessage("INFO |xxxxxx|TestBody|This is log message number 32\r\n"));
    EXPECT_THAT(mka_debug_buffer[1U], LoggingMessage("INFO |xxxxxx|TestBody|This is log message number 33\r\n"));
    EXPECT_THAT(mka_debug_buffer[2U], LoggingMessage("INFO |xxxxxx|TestBody|This is log message number 2\r\n"));
}

TEST_F(events, event_with_logging)
{
    MKA_EVENT(MKA_EVENT_INIT);
    EXPECT_EQ(1U, mka_debug_buffer_idx);
    EXPECT_THAT(mka_debug_buffer[0U], LoggingMessage("DEBUG|xxxxxx|TestBody|Event [MKA_EVENT_INIT]\r\n"));

    MKA_BUS_EVENT(4U, MKA_EVENT_INIT);
    EXPECT_EQ(2U, mka_debug_buffer_idx);
    EXPECT_THAT(mka_debug_buffer[1U], LoggingMessage("DEBUG|xxxxxx|TestBody|Event [MKA_EVENT_INIT] on bus 4\r\n"));
}
