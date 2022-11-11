/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_fsm.h
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
 * @file        mka_fsm.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA types abstraction
 *
 * @{
 */

/* FSM definition example
 *
 * / / ------- types area -----------
 *
 * typedef enum {           / / All the states go here in this enum
 *         STATE_INITIAL,
 *         STATE_START,
 *         STATE_WORK,
 *         STATE_END
 * } t_fsm_state_DummyFSM; / / Name is important: t_fsm_state_ + name of your FSM
 * 
 * typedef struct {
 *     FSM_DECLARE_MEMBER(DummyFSM);
 *
 *     uint32_t implementer_variable_1;
 *     uint32_t implementer_variable_2;
 *     ...
 * 
 * } t_fsm_DummyFSM;    / / This is the object that represents a FSM
 *
 * 
 * / / ------- prototypes area -----------
 *
 * FSM_DECLARE_ACTIVITY_FUNC(DummyFSM);
 * FSM_DECLARE_INITIAL_STATE(DummyFSM, STATE_INITIAL);
 * FSM_DECLARE_STATE(DummyFSM, STATE_START);
 * FSM_DECLARE_STATE(DummyFSM, STATE_WORK);
 * FSM_DECLARE_STATE(DummyFSM, STATE_END);
 *
 *
 * / / ------- implementation area --------
 *
 * FSM_IMPLEMENT_ENTRY_FUNC(DummyFSM, STATE_INITIAL)
 * {
 *     Code to execute on state entry
 *     fsm->implementer_variable_1 = 0U;
 *     ...
 * }
 *
 * FSM_IMPLEMENT_ENTRY_FUNC(DummyFSM, STATE_START)
 * ...
 *
 * FSM_IMPLEMENT_ACTIVITY_FUNC(DummyFSM)
 * {
 *     User code to transition the state machine
 *     if (fsm->reset_requested) { / / EXAMPLE!
 *         FSM_TRANSITION(DummyFSM, STATE_START);
 *     }
 *     else {
 *         switch(fsm->state) {
 *             case STATE_INITIAL:
 *                 FSM_TRANSITION(DummyFSM, STATE_START);
 *                 break;
 *             case STATE_START:
 *             ...
 *         }
 *     }
 * }
 *
 * To initialise the state machine:
 *
 *   FSM_INIT(DummyFSM, &fsm_inst);
 *
 * (inside area that is going to cycle the FSM)
 *
 *   FSM_RUN_UNTIL_STABLE(DummyFSM, &fsm_inst);
 *
 * (or, in case only one tick is desired)
 *
 *   FSM_RUN(DummyFSM, &fsm_inst);
 *
 */

#ifndef MKA_FSM_H_
#define MKA_FSM_H_

/*******************        Includes        *************************/
#include "mka_private.h"

//lint -estring(715, is_fsm_executing_entry) [MISRA 2012 Rule 2.7, advisory] Depending on the implementation of the entry function, this variable could be left unused
//lint -estring(715, fsm) [MISRA 2012 Rule 2.7, advisory] Depending on the implementation of the entry function, this variable could be left unused
//lint -estring(818, fsm) [MISRA 2012 Rule 8.13, advisory] Some implementations may not modify FSM state, but this is not enough reason to change the prototype to const
//lint -estring(9003, fsm_initial_state_*) [MISRA 2012 Rule 8.9, advisory] Not possible to define variable at block scope with the preprocessor strategy taken

//lint -save
//lint -e9026 [MISRA 2012 Directive 4.9, advisory] this module implements function-like macros for making code more readable and less error prone 
//lint -e9024 [MISRA 2012 Rule 20.10, advisory] #/## operator necessary to combine literals from macros into types/variables/functions
//lint -e9023 [MISRA 2012 Rule 1.3, required] #/## operator necessary to combine literals from macros into types/variables/functions

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/

/* Construction macros ---------------------------------------------------- */

/**
 * This macro is intended to be used to declare member elements in the struct that \n
 * represents the FSM object.
 *
 * @param[in] fsm_name  Literal name of the state machine
 */
#define FSM_DECLARE_MEMBER(fsm_name) \
    t_fsm_state_ ## fsm_name    state; \
    t_MKA_bus                   bus

/**
 * This macro is intended to declare each non-initial state of the FSM. It internally \n
 * declares the private functions so that they can be referenced inside the file.
 *
 * @param[in] fsm_name      Literal name of the state machine
 * @param[in] state_name    Literal name of the referenced state in the state machine
 */
#define FSM_DECLARE_STATE(fsm_name, state_name) \
    static void fsm_entry_func_ ## fsm_name ## _ ## state_name(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry)

/**
 * This macro is intended to be used to declare the INITIAL state of the FSM. It internally \n
 * declares the private functions and references so that they can be used inside the file.
 *
 * @param[in] fsm_name  Literal name of the state machine
 * @param[in] state_name    Literal name of the referenced state in the state machine
 */
#if (MKA_CFG_LOGGING_LEVEL >= MKA_LOGLEVEL_DEBUG) && (MKA_CFG_VERBOSITY >= 2U)
# define FSM_DECLARE_INITIAL_STATE(fsm_name, state_name) \
    static const t_fsm_state_ ## fsm_name fsm_initial_state_ ## fsm_name = state_name; \
    static const char *const fsm_initial_state_ ## fsm_name ## _str = #state_name; \
    static void fsm_entry_func_ ## fsm_name ## _ ## state_name(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry); \
    static void(* fsm_initial_state_ ## fsm_name ## _fnc)(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry) = \
                fsm_entry_func_ ## fsm_name ## _ ## state_name
#else
# define FSM_DECLARE_INITIAL_STATE(fsm_name, state_name) \
    static const t_fsm_state_ ## fsm_name fsm_initial_state_ ## fsm_name = state_name; \
    static void fsm_entry_func_ ## fsm_name ## _ ## state_name(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry); \
    static void(* fsm_initial_state_ ## fsm_name ## _fnc)(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry) = \
                fsm_entry_func_ ## fsm_name ## _ ## state_name
#endif

/**
 * This macro declares the prototype for the FSM activity function.
 *
 * @param[in] fsm_name  Literal name of the state machine
 */
#define FSM_DECLARE_ACTIVITY_FUNC(fsm_name) \
    static void fsm_activity_func_ ## fsm_name(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry)

/**
 * This macro declares the prototype for the FSM entry function.
 *
 * @param[in] fsm_name  Literal name of the state machine
 */
#define FSM_IMPLEMENT_ENTRY_FUNC(fsm_name, state_name) \
    static void fsm_entry_func_ ## fsm_name ## _ ## state_name(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry)

/**
 * This macro is intended to be used as a declarator of the FSM activity function. \n
 * \n
 * The activity function is executed at each FSM tick, and its purpose is to TRANSITION the state machine \n
 * to new states if necessary. To create a Moore state machine, no further actions are expected in this part. \n
 *
 * @remark Inside this implementation is the only place where transitions can ocurr.
 *
 * @param[in] fsm_name  Literal name of the state machine
 */
#define FSM_IMPLEMENT_ACTIVITY_FUNC(fsm_name) \
    static void fsm_activity_func_ ## fsm_name(t_fsm_ ## fsm_name *const fsm, bool const is_fsm_executing_entry)\


/* Function-like callable macros ----------------------------------------- */

/**
 * This callable macro initialises a state machine. The initial state shall be set, the action logged, and the entry \n
 * implementation of the initial state shall be called.
 *
 * @remark This activity is logged from verbosity 2.
 *
 * @param[in] fsm_name      Literal name of the state machine
 * @param[in] fsm_obj_ptr   Pointer to struct that represents the state machine
 */
#define FSM_INIT(fsm_name, fsm_obj_ptr, bus_id) \
    /*lint -e{717} do...while(0) allows to code a functionality as a single C sentence, which is less error prone */ \
    /*lint -e{9036} [MISRA 2012 Rule 14.4, required] any compiler understands "0" as a constant false condition */ \
    do {\
        MKA_LOG_DEBUG2("FSM " #fsm_name "/%i initialised (%s)", (bus_id), fsm_initial_state_ ## fsm_name ## _str); \
        (fsm_obj_ptr)->bus = bus_id; \
        (fsm_obj_ptr)->state = fsm_initial_state_ ## fsm_name; \
        fsm_initial_state_ ## fsm_name ## _fnc(fsm_obj_ptr, true); \
    } while(0)

/**
 * This callable macro runs exactly one tick of the FSM. \n
 * The activity function shall be invoked and if determined by the activity function, a transition could occur. \n
 *
 * @remark This activity is logged from verbosity 3.
 *
 * @param[in] fsm_name      Literal name of the state machine
 * @param[in] fsm_obj_ptr   Pointer to struct that represents the state machine
 */
#define FSM_RUN(fsm_name, fsm_obj_ptr) \
    /*lint -e{717} do...while(0) allows to code a functionality as a single C sentence, which is less error prone */ \
    /*lint -e{9036} [MISRA 2012 Rule 14.4, required] any compiler understands "0" as a constant false condition */ \
    do {\
        MKA_LOG_DEBUG3("FSM " #fsm_name "/%i runs", (fsm_obj_ptr)->bus); \
        /* Break potential function call loops by preventing transitions in transition code */ \
        fsm_activity_func_ ## fsm_name(fsm_obj_ptr, false); \
    } while(0)

/**
 * This callable macro runs multiple ticks of the FSM until the state converges. \n
 * The activity function shall be invoked and if determined by the activity function, transitions could occur. \n
 *
 * @remark This activity is logged from verbosity 3.
 * @remark If the FSM does not converge in 100 ticks, an ASSERT shall be triggered.
 *
 * @param[in] fsm_name      Literal name of the state machine
 * @param[in] fsm_obj_ptr   Pointer to struct that represents the state machine
 */
#define FSM_RUN_UNTIL_STABLE(fsm_name, fsm_obj_ptr) \
    /*lint -e{717} do...while(0) allows to code a functionality as a single C sentence, which is less error prone */ \
    /*lint -e{9036} [MISRA 2012 Rule 14.4, required] any compiler understands "0" as a constant false condition */ \
    do { \
        MKA_LOG_DEBUG3("FSM " #fsm_name "/%i runs until stable", (fsm_obj_ptr)->bus); \
        t_fsm_state_ ## fsm_name currentState = (fsm_obj_ptr)->state; \
        t_fsm_state_ ## fsm_name previousState = (fsm_obj_ptr)->state; \
        uint16_t maxIterations = 100U; \
        do { \
            previousState = currentState; \
            MKA_LOG_DEBUG3("FSM " #fsm_name "/%i tick [%i]", (fsm_obj_ptr)->bus, currentState); \
            fsm_activity_func_ ## fsm_name(fsm_obj_ptr, false); \
            currentState = (fsm_obj_ptr)->state; \
            --maxIterations; \
        } while ((currentState != previousState) && (maxIterations > 0U)); \
        MKA_ASSERT(maxIterations > 0U, "FSM " #fsm_name "/%i failed to achieve a stable state!", (fsm_obj_ptr)->bus); \
        MKA_LOG_DEBUG3("FSM " #fsm_name "/%i finished execution in state [%i]", (fsm_obj_ptr)->bus, currentState); \
    } while(0)

/**
 * This callable macro performs a transition . \n
 * The activity function shall be invoked and if determined by the activity function, transitions could occur. \n
 *
 * @remark This activity is logged from verbosity 2.
 * @remark Transitions can only occurr for now inside the activity code. An assert shall be triggered otherwise.
 *
 * @param[in] fsm_name      Literal name of the state machine
 * @param[in] fsm_obj_ptr   Pointer to struct that represents the state machine
 */
#define FSM_TRANSITION(fsm_name, new_state) \
    /*lint -e{717} do...while(0) allows to code a functionality as a single C sentence, which is less error prone */ \
    /*lint -e{9036} [MISRA 2012 Rule 14.4, required] any compiler understands "0" as a constant false condition */ \
    do { \
        MKA_ASSERT(!is_fsm_executing_entry, "FSM implementation error: Transitions in FSM_ENTRY_FUNC are forbidden"); \
        /*lint -e{774} [MISRA 2012 Rule 14.3, required] compiler is expected to optimise a potential constant condition */ \
        if (!is_fsm_executing_entry) { \
            MKA_LOG_DEBUG1("FSM " #fsm_name "/%i transitions to state " #new_state, fsm->bus); \
            fsm->state = new_state; \
            fsm_entry_func_ ## fsm_name ## _ ## new_state(fsm, true); \
            MKA_LOG_DEBUG3("FSM " #fsm_name "/%i finished entry code", fsm->bus); \
        } \
    } while(0)


/*******************        Types             ***********************/

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/

#ifdef __cplusplus
}
#endif

#endif /* MKA_FSM_H_ */

//lint -restore

/** @} */

