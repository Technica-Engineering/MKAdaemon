/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-log.cpp
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

struct CMocks {
    static CMocks* inst;
    CMocks(void) {
        assert(((void)"Duplicated object!", (inst==NULL)));
        inst = this;
    }
    ~CMocks(void) {
        inst = NULL;
    }

    MOCK_METHOD0( assertion_action, void(void));
    MOCK_METHOD2( print_action, void(char const*, unsigned long));
    MOCK_METHOD2( event_action, void(t_MKA_bus, t_MKA_event));
};

CMocks* CMocks::inst = nullptr;
extern "C" void mock_assertion_action(void)
{
    assert(((void)"UT error: object Mocks not instantiated", (CMocks::inst != NULL)));
    CMocks::inst->assertion_action();
}
extern "C" void mock_print(char const* text, unsigned long length)
{
    assert(((void)"UT error: object Mocks not instantiated", (CMocks::inst != NULL)));
    CMocks::inst->print_action(text, length);
}
extern "C" void mock_event(t_MKA_bus bus, t_MKA_event event)
{
    assert(((void)"UT error: object Mocks not instantiated", (CMocks::inst != NULL)));
    CMocks::inst->event_action(bus, event);
}

struct logging : public ::testing::Test { CMocks mocks; };
struct events : public ::testing::Test { CMocks mocks; };

TEST_F(logging, assert_positive)
{
    EXPECT_CALL(mocks, assertion_action()) .Times(0);
    EXPECT_CALL(mocks, print_action(_,_)) .Times(0);
    MKA_ASSERT(1 == 1, "Test assertion message");
}

TEST_F(logging, assert_negative)
{
    EXPECT_CALL(mocks, assertion_action()) .Times(1);
    EXPECT_CALL(mocks, print_action(_,_)) .Times(1);
    MKA_ASSERT(1 == 0, "Test assertion message");
}

TEST_F(logging, assert_messsage)
{
    /* Compare beginning of the message (skipping line number!) */
    EXPECT_CALL(mocks, assertion_action()) .Times(1);
    EXPECT_CALL(mocks, print_action(
            LoggingMessage("ERROR|xxxxxx|TestBody|ASSERT FAIL: Test assertion message\r\n"),
            59)
    ) .Times(1);
    MKA_ASSERT(1 == 0, "Test assertion message");
}

TEST_F(logging, info_message)
{
#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG
    EXPECT_CALL(mocks, print_action(
            LoggingMessage("INFO |xxxxxx|TestBody|Info message\r\n"),
            36)
    ) .Times(1);
#else
    EXPECT_CALL(mocks, print_action(_,_)) .Times(0);
#endif
    MKA_LOG_INFO("Info message");
}

TEST_F(logging, warning_message)
{
#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_WARNING
    EXPECT_CALL(mocks, print_action(
            LoggingMessage("WARN |xxxxxx|TestBody|Warning message\r\n"),
            39)
    ) .Times(1);
#else
    EXPECT_CALL(mocks, print_action(_,_)) .Times(0);
#endif
    MKA_LOG_WARNING("Warning message");
}

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_WARNING
TEST_F(logging, warning_formatting)
{
    EXPECT_CALL(mocks, print_action(
            LoggingMessage("WARN |xxxxxx|TestBody|Char: z Int: 12345 String: hello\r\n"),
            56)
    ) .Times(1);
    MKA_LOG_WARNING("Char: %c Int: %i String: %s", 'z', 12345, "hello");
}
#endif

TEST_F(logging, error_message)
{
#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_ERROR
    EXPECT_CALL(mocks, print_action(
            LoggingMessage("ERROR|xxxxxx|TestBody|Error message\r\n"),
            37)
    ) .Times(1);
#else
    EXPECT_CALL(mocks, print_action(_,_)) .Times(0);
#endif
    MKA_LOG_ERROR("Error message");
}

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG
TEST_F(logging, debug_message)
{
    EXPECT_CALL(mocks, print_action(
            LoggingMessage("DEBUG|xxxxxx|TestBody|Debugging message\r\n"),
            41)
    ) .Times(1);
    MKA_LOG_DEBUG0("Debugging message");
}

# if MKA_CFG_VERBOSITY <= 2
TEST_F(logging, verbose_filter_pass)
{
    EXPECT_CALL(mocks, print_action(
            LoggingMessage("DEBUG|xxxxxx|TestBody|Debugging message\r\n"),
            41)
    ) .Times(1);
    MKA_LOG_DEBUG2("Debugging message");
}
# endif

# if MKA_CFG_VERBOSITY <= 2
TEST_F(logging, verbose_filter_block)
{
    EXPECT_CALL(mocks, print_action(_,_)) .Times(0);
    MKA_LOG_DEBUG3("Debugging message");
}
# endif
#else /* MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG */
TEST_F(logging, debug_message_filtered)
{
    EXPECT_CALL(mocks, print_action(_,_)) .Times(0);
    MKA_LOG_DEBUG0("Debugging message");
}
#endif

TEST_F(events, event_with_logging)
{
#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG
    EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|TestBody|Event [MKA_EVENT_INIT]\r\n"), _)) .Times(1);
#else
    EXPECT_CALL(mocks, print_action(_, _)) .Times(0);
#endif
    EXPECT_CALL(mocks, event_action(MKA_BUS_NONE, MKA_EVENT_INIT)) .Times(1);
    MKA_EVENT(MKA_EVENT_INIT);

#if MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG
    EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|TestBody|Event [MKA_EVENT_INIT] on bus 4\r\n"), _)) .Times(1);
#else
    EXPECT_CALL(mocks, print_action(_, _)) .Times(0);
#endif
    EXPECT_CALL(mocks, event_action(4, MKA_EVENT_INIT)) .Times(1);
    MKA_BUS_EVENT(4, MKA_EVENT_INIT);
}

