/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-fsm.cpp
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
#include "mka_fsm.h"

typedef enum {
        STATE_INITIAL,
        STATE_START,
        STATE_WORK,
        STATE_END
} t_fsm_state_DummyFSM;

typedef struct {
    FSM_DECLARE_MEMBER(DummyFSM);

} t_fsm_DummyFSM;


FSM_DECLARE_INITIAL_STATE(DummyFSM, STATE_INITIAL);
FSM_DECLARE_STATE(DummyFSM, STATE_START);
FSM_DECLARE_STATE(DummyFSM, STATE_WORK);
FSM_DECLARE_STATE(DummyFSM, STATE_END);

FSM_DECLARE_ACTIVITY_FUNC(DummyFSM);

struct CMocks {
    static CMocks* inst;
    CMocks(void) {
        assert(((void)"Duplicated object!", (inst==NULL)));
        inst = this;
    }
    ~CMocks(void) {
        inst = NULL;
    }

    static CMocks* get(void) {
        assert(((void)"UT error: object Mocks not instantiated", (CMocks::inst != NULL)));
        return inst;
    }

    bool                    entry_try_transition;
    uint32_t                do_transition;
    t_fsm_state_DummyFSM    state_to_transition[16U];

    void consume_transition(void) {
        --do_transition;
        memmove(&state_to_transition[0], &state_to_transition[1],
            sizeof(state_to_transition)-sizeof(state_to_transition[0]));
    }

    MOCK_METHOD0( runs_entry_initial, void(void));
    MOCK_METHOD0( runs_entry_start, void(void));
    MOCK_METHOD0( runs_entry_work, void(void));
    MOCK_METHOD0( runs_entry_end, void(void));
    MOCK_METHOD0( runs_activity, void(void));

    MOCK_METHOD0( assertion_action, void(void));
    MOCK_METHOD2( print_action, void(char const*, unsigned long));
    MOCK_METHOD2( event_action, void(t_MKA_bus, t_MKA_event));
};
CMocks* CMocks::inst = nullptr;

extern "C" void mock_assertion_action(void)
{
    CMocks::get()->assertion_action();
}
extern "C" void mock_print(char const* text, unsigned long length)
{
    CMocks::get()->print_action(text, length);
}
extern "C" void mock_event(t_MKA_bus bus, t_MKA_event event)
{
    CMocks::get()->event_action(bus, event);
}

FSM_IMPLEMENT_ENTRY_FUNC(DummyFSM, STATE_INITIAL)
{
    CMocks::get()->runs_entry_initial();
    if (CMocks::get()->entry_try_transition)
        FSM_TRANSITION(DummyFSM, STATE_WORK);
}

FSM_IMPLEMENT_ENTRY_FUNC(DummyFSM, STATE_START)
{
    CMocks::get()->runs_entry_start();
    if (CMocks::get()->entry_try_transition)
        FSM_TRANSITION(DummyFSM, STATE_WORK);
}

FSM_IMPLEMENT_ENTRY_FUNC(DummyFSM, STATE_WORK)
{
    CMocks::get()->runs_entry_work();
    if (CMocks::get()->entry_try_transition)
        FSM_TRANSITION(DummyFSM, STATE_WORK);
}

FSM_IMPLEMENT_ENTRY_FUNC(DummyFSM, STATE_END)
{
    CMocks::get()->runs_entry_end();
    if (CMocks::get()->entry_try_transition)
        FSM_TRANSITION(DummyFSM, STATE_WORK);
}

FSM_IMPLEMENT_ACTIVITY_FUNC(DummyFSM)
{
    CMocks::get()->runs_activity();
    if (CMocks::get()->do_transition > 0U) {
        switch(CMocks::get()->state_to_transition[0U]) {
        case STATE_INITIAL:
            FSM_TRANSITION(DummyFSM, STATE_INITIAL);
            break;
        case STATE_START:
            FSM_TRANSITION(DummyFSM, STATE_START);
            break;
        case STATE_WORK:
            FSM_TRANSITION(DummyFSM, STATE_WORK);
            break;
        case STATE_END:
            FSM_TRANSITION(DummyFSM, STATE_END);
            break;
        default:
            break;
        }
        CMocks::get()->consume_transition();
    }
}

struct fsm_activity : public ::testing::Test {
    CMocks mocks;
    t_fsm_DummyFSM fsm_inst;

    virtual void SetUp(void) {
        mocks.entry_try_transition = false;
        mocks.do_transition = 0U;
        EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|SetUp|FSM DummyFSM/5 initialised (STATE_INITIAL)\r\n"), _)) .Times(1);
        EXPECT_CALL(mocks, runs_entry_initial()) .Times(1);
        FSM_INIT(DummyFSM, &fsm_inst, 5U);
    }

    void test_run(void) {
        EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|test_run|FSM DummyFSM/5 runs\r\n"), _)) .Times(1);
        FSM_RUN(DummyFSM, &fsm_inst);
    }

    void test_run_until_stable(void) {
        EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|test_run_until_stable|FSM DummyFSM/5 runs until stable\r\n"), _)) .Times(1);
        EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|test_run_until_stable|FSM DummyFSM/5 finished execution in state"), _)) .Times(1);
        FSM_RUN_UNTIL_STABLE(DummyFSM, &fsm_inst);
    }
};

TEST_F(fsm_activity, initial_state)
{
    ASSERT_EQ(STATE_INITIAL, fsm_inst.state);
}

TEST_F(fsm_activity, tick)
{
    EXPECT_CALL(mocks, runs_activity()) .Times(1);
    test_run();
    ASSERT_EQ(STATE_INITIAL, fsm_inst.state);
}

TEST_F(fsm_activity, transition)
{
    mocks.do_transition = 1U;
    mocks.state_to_transition[0] = STATE_START;

    EXPECT_CALL(mocks, runs_activity()) .Times(1);
    EXPECT_CALL(mocks, runs_entry_start()) .Times(1);

    EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|fsm_activity_func_DummyFSM|FSM DummyFSM/5 transitions to state STATE_START\r\n"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|fsm_activity_func_DummyFSM|FSM DummyFSM/5 finished entry code\r\n"), _)) .Times(1);

    test_run();
    ASSERT_EQ(STATE_START, fsm_inst.state);
}

TEST_F(fsm_activity, transition_in_entry_fails)
{
    mocks.do_transition = 1U;
    mocks.state_to_transition[0] = STATE_START;
    mocks.entry_try_transition = true;

    EXPECT_CALL(mocks, print_action(LoggingMessage("ERROR|xxxxxx|fsm_entry_func_DummyFSM_STATE_START|ASSERT FAIL: FSM implementation error: Transitions in FSM_ENTRY_FUNC are forbidden\r\n"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|fsm_activity_func_DummyFSM|FSM DummyFSM/5 transitions to state STATE_START\r\n"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessage("DEBUG|xxxxxx|fsm_activity_func_DummyFSM|FSM DummyFSM/5 finished entry code\r\n"), _)) .Times(1);

    EXPECT_CALL(mocks, runs_activity()) .Times(1);
    EXPECT_CALL(mocks, runs_entry_start()) .Times(1);
    EXPECT_CALL(mocks, assertion_action()) .Times(1);

    test_run();
}


TEST_F(fsm_activity, multiple_transitions)
{
    mocks.do_transition = 3U;
    mocks.state_to_transition[0] = STATE_START;
    mocks.state_to_transition[1] = STATE_WORK;
    mocks.state_to_transition[2] = STATE_END;

    EXPECT_CALL(mocks, print_action(_, _)) .Times(AnyNumber());

    EXPECT_CALL(mocks, runs_activity()) .Times(4);
    EXPECT_CALL(mocks, runs_entry_start()) .Times(1);
    EXPECT_CALL(mocks, runs_entry_work()) .Times(1);
    EXPECT_CALL(mocks, runs_entry_end()) .Times(1);

    test_run_until_stable();
}

