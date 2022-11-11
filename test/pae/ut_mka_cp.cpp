/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: ut_mka_cp.cpp
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

/* Description: TCA9539
 *
 * Execute the following command to run this test alone, without coverage:
 * $ python waf test --targets=test_name --coverage=no
 *
 * Execute the following command to run ALL tests:
 * $ python waf test
 *
 */
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stddef.h>

#include <future> ///for async. Note: async calls do not require expectations.

#include "mocks.h"
#include "ut_helpers.h"

#include "mka_cp.h"

#define MKA_BUS 0

#define EXPECT_OLD_SA(bus_, oki_, oan_, otx_, orx_) do { \
    t_MKA_ki const*oki; uint8_t oan; bool otx; bool orx; \
    MKA_CP_GetOldSA(bus_, &oki, &oan, &otx, &orx); \
    EXPECT_THAT(oki, KICompare(&(oki_)))  << "Old KI mismatch"; \
    EXPECT_THAT(oan, Eq(oan_))            << "Old AN mismatch"; \
    EXPECT_THAT(otx, Eq(otx_))            << "Old TX mismatch"; \
    EXPECT_THAT(orx, Eq(orx_))            << "Old RX mismatch"; \
} while(0)

#define EXPECT_LAT_SA(bus_, lki_, lan_, ltx_, lrx_) do { \
    t_MKA_ki const*lki; uint8_t lan; bool ltx; bool lrx; \
    MKA_CP_GetLatestSA(bus_, &lki, &lan, &ltx, &lrx); \
    EXPECT_THAT(lki, KICompare(&(lki_)))  << "Latest KI mismatch"; \
    EXPECT_THAT(lan, Eq(lan_))            << "Latest AN mismatch"; \
    EXPECT_THAT(ltx, Eq(ltx_))            << "Latest TX mismatch"; \
    EXPECT_THAT(lrx, Eq(lrx_))            << "Latest RX mismatch"; \
} while(0)

extern "C" void MKA_CP_MainFunctionTick(t_MKA_bus bus);
extern "C" void mock_assertion_action(void){ }
extern "C" void mock_print(char const* text, unsigned long length)
{
    printf("%s\n", text);
}

uint32_t mka_tick_time_ms;

static bool PROTECT_FRAMES;
static t_MKA_validate_frames VALIDATE_FRAMES;
static bool REPLAY_PROTECT;
static uint32_t REPLAY_WINDOW;
static t_MKA_ki ZERO_KI;
static t_MKA_ki DISTRIBUTED_KI_1;
static uint8_t DISTRIBUTED_AN_1;
static t_MKA_ki DISTRIBUTED_KI_2;
static uint8_t DISTRIBUTED_AN_2;
static t_MKA_ki DISTRIBUTED_KI_3;
static uint8_t DISTRIBUTED_AN_3;
static t_MKA_SECY_config test_secy_config_1;
static t_MKA_SECY_config test_secy_config_2;

t_MKA_global_config const* MKA_active_global_config = NULL;

/*ACTION_P(GetKI, varPtr) {
    return memcpy(varPtr, arg1, sizeof(t_MKA_ki));
}*/

MATCHER_P(KICompare, varPtr, "Matcher to compare KI") {
    if(arg != NULL) {
        return (memcmp(arg,varPtr,sizeof(t_MKA_ki)) == 0);
    }
    else {
        return false;
    }
}

MATCHER_P(CompareSecYConfig, varPtr, "Matcher to compare t_MKA_SECY_config") {
    if (memcmp(arg,varPtr,sizeof(t_MKA_SECY_config)) != 0) {
        printf("protect_frames Arg: %d, Test: %d \n", arg->protect_frames, varPtr->protect_frames);
        printf("replay_protect Arg: %d, Test: %d \n", arg->replay_protect, varPtr->replay_protect);
        printf("replay_window Arg: %d, Test: %d \n", arg->replay_window, varPtr->replay_window);
        printf("validate_frames Arg: %d, Test: %d \n", arg->validate_frames, varPtr->validate_frames);
        printf("current_cipher_suite Arg: %lu, Test: %lu \n", arg->current_cipher_suite, varPtr->current_cipher_suite);
        printf("confidentiality_offset Arg: %d, Test: %d \n", arg->confidentiality_offset, varPtr->confidentiality_offset);
        printf("controlled_port_enabled Arg: %d, Test: %d \n", arg->controlled_port_enabled, varPtr->controlled_port_enabled);
        return false;
    }
    return true;
}

class Test_MKA_CP_Base : public ::testing::Test {
   protected:
   public:
    Mock::Mocks mocks;
    t_MKA_global_config test_global_active_config = {
        .hello_time = 2000U,
        .bounded_hello_time = 500U,
        .life_time = 6000U,
        .sak_retire_time = 3000U,
        .hello_rampup = { 100U, 200U, 400U, 800U, 800U },
        .hello_rampup_number = 5U,
        .transmit_empty_dist_sak = MKA_ON,
        .transmit_empty_sak_use = MKA_ON,
        .transmit_null_xpn = MKA_OFF,
        .secy_polling_ms = 5U
    };

    virtual void SetUp(void)
    {
        PROTECT_FRAMES = true;
        VALIDATE_FRAMES = MKA_VALIDATE_STRICT;
        REPLAY_PROTECT = true;
        REPLAY_WINDOW = 1000U;
        memset(&ZERO_KI,0U,sizeof(t_MKA_ki));
        for (int i = 0; i<MKA_MI_LENGTH;i++) {
            DISTRIBUTED_KI_1.mi[i] = i;
            DISTRIBUTED_KI_2.mi[i] = MKA_MI_LENGTH - i;
            DISTRIBUTED_KI_2.mi[i] = MKA_MI_LENGTH + i;
        }
        DISTRIBUTED_KI_1.kn = 0x44332211U;
        DISTRIBUTED_KI_2.kn = 0x11223344U;
        DISTRIBUTED_KI_3.kn = 0x55667788U;
        DISTRIBUTED_AN_1 = 0xAB;
        DISTRIBUTED_AN_2 = 0xBA;
        DISTRIBUTED_AN_3 = 0xCD;
        mka_tick_time_ms = 30000U;

        MKA_active_global_config = &test_global_active_config;
    }

    virtual void TearDown(void)
    {
    }

    void ExpectedCallsEntryToINIT(void)
    {
        /* GetKAY info */
        EXPECT_CALL(mocks, MKA_KAY_GetProtectFrames(MKA_BUS))
            .WillOnce(Return(PROTECT_FRAMES));
        EXPECT_CALL(mocks, MKA_KAY_GetValidateFrames(MKA_BUS))
            .WillOnce(Return(VALIDATE_FRAMES));
        EXPECT_CALL(mocks, MKA_KAY_GetReplayProtect(MKA_BUS))
            .WillOnce(Return(REPLAY_PROTECT));
        EXPECT_CALL(mocks, MKA_KAY_GetReplayWindow(MKA_BUS))
            .WillOnce(Return(REPLAY_WINDOW));

        /* portValid EVENT */
        EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = false;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);
    }

    void FromFSMInitToINITState(void)
    {
        ExpectedCallsEntryToINIT();

        MKA_CP_Init((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
    }

    void FromFSMInitToChangeState(void)
    {
        FromFSMInitToINITState();

        MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);

        /* Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI) ))
            .Times(2);

        /* portValid EVENT */
        EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = false;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
    }

    void FromChangeStateToAllowedState(void)
    {
        FromFSMInitToChangeState();

        MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
        MKA_CP_ConnectUnauthenticated((t_MKA_bus)MKA_BUS);

        /* portValid EVENT */
        EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = false;
        test_secy_config_1.replay_protect = false;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = MKA_VALIDATE_CHECKED;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
    }

    void FromChangeStateToAuthenticatedState(void)
    {
        FromFSMInitToChangeState();

        MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
        MKA_CP_ConnectAuthenticated((t_MKA_bus)MKA_BUS);

        /* portValid EVENT */
        EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = false;
        test_secy_config_1.replay_protect = false;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = MKA_VALIDATE_CHECKED;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
    }

    void FromChangeStateToSecuredState(void)
    {
        FromFSMInitToChangeState();

        MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
        MKA_CP_ConnectSecure((t_MKA_bus)MKA_BUS);

        /* portValid EVENT */
        EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_VALID))
            .Times(1);

        /* GetKAY info */
        EXPECT_CALL(mocks, MKA_KAY_GetProtectFrames(MKA_BUS))
            .WillOnce(Return(PROTECT_FRAMES));
        EXPECT_CALL(mocks, MKA_KAY_GetValidateFrames(MKA_BUS))
            .WillOnce(Return(VALIDATE_FRAMES));
        EXPECT_CALL(mocks, MKA_KAY_GetReplayProtect(MKA_BUS))
            .WillOnce(Return(REPLAY_PROTECT));
        EXPECT_CALL(mocks, MKA_KAY_GetReplayWindow(MKA_BUS))
            .WillOnce(Return(REPLAY_WINDOW));

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = false;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
    }

    void FromSecuredStateToReceiveState(void)
    {
        FromChangeStateToSecuredState();

        MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
        MKA_CP_ConnectSecure((t_MKA_bus)MKA_BUS);
        MKA_CP_SignalNewSAK((t_MKA_bus)MKA_BUS);
        MKA_CP_SetDistributedKI((t_MKA_bus)MKA_BUS,&DISTRIBUTED_KI_1);
        MKA_CP_SetDistributedAN((t_MKA_bus)MKA_BUS,DISTRIBUTED_AN_1);

        /* Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_CreateSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_1) ))
            .Times(1);
        EXPECT_CALL(mocks, MKA_KAY_EnableReceiveSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_1) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = false;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, false, false);
    }

    void PAEKeyServer_FromReceiveStateToTransmitState_ControlledPortDisabled(void)
    {
        FromSecuredStateToReceiveState();

        MKA_CP_SetUsingReceiveSAs((t_MKA_bus)MKA_BUS, true);
        MKA_CP_SetElectedSelf((t_MKA_bus)MKA_BUS, true);
        MKA_CP_SetAllReceiving((t_MKA_bus)MKA_BUS, false);

        /* TRANSMIT Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_EnableTransmitSA(MKA_BUS, KICompare(&DISTRIBUTED_KI_1) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = false;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);
        test_secy_config_2.protect_frames = PROTECT_FRAMES;
        test_secy_config_2.replay_protect = REPLAY_PROTECT;
        test_secy_config_2.replay_window = REPLAY_WINDOW;
        test_secy_config_2.validate_frames = VALIDATE_FRAMES;
        test_secy_config_2.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_2.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_2.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_2)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, false, true);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
    }

    void PAENOKeyServer_FromReceiveStateToTransmitState_ControlledPortDisabled(void)
    {
        FromSecuredStateToReceiveState();

        MKA_CP_SetUsingReceiveSAs((t_MKA_bus)MKA_BUS, true);
        MKA_CP_SetElectedSelf((t_MKA_bus)MKA_BUS, false);

        /* READY Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_SignalNewInfo(MKA_BUS))
            .Times(1);

        /* TRANSMIT Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_EnableTransmitSA(MKA_BUS, KICompare(&DISTRIBUTED_KI_1) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = false;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(2);
        test_secy_config_2.protect_frames = PROTECT_FRAMES;
        test_secy_config_2.replay_protect = REPLAY_PROTECT;
        test_secy_config_2.replay_window = REPLAY_WINDOW;
        test_secy_config_2.validate_frames = VALIDATE_FRAMES;
        test_secy_config_2.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_2.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_2.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_2)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, false, true);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, false, true);
    
        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
    }

    void FromTransmitStateToRetireState_ORxFalse(void)
    {
        PAEKeyServer_FromReceiveStateToTransmitState_ControlledPortDisabled();

        MKA_CP_SetUsingTransmitSA((t_MKA_bus)MKA_BUS, true);

        /* TRANSMITTING Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_SignalNewInfo(MKA_BUS))
            .Times(1);

        /* RETIRE Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(2);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
    }

    void FromRetireStateToReceiveState_NewSak(void)
    {
        FromTransmitStateToRetireState_ORxFalse();

        MKA_CP_SignalNewSAK((t_MKA_bus)MKA_BUS);
        MKA_CP_SetDistributedKI((t_MKA_bus)MKA_BUS,&DISTRIBUTED_KI_2);
        MKA_CP_SetDistributedAN((t_MKA_bus)MKA_BUS,DISTRIBUTED_AN_2);
        MKA_CP_SetUsingReceiveSAs((t_MKA_bus)MKA_BUS, false);

        /* Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_CreateSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_2) ))
            .Times(1);
        EXPECT_CALL(mocks, MKA_KAY_EnableReceiveSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_2) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, false, false);
    }

    void FromReceiveStateToReceivingState(void)
    {
        FromRetireStateToReceiveState_NewSak();

        MKA_CP_SetUsingReceiveSAs((t_MKA_bus)MKA_BUS, true);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, false, true);
    }

    void FromReceivingStateToReceiveState_NewSak(void)
    {
        FromReceiveStateToReceivingState();

        MKA_CP_SignalNewSAK((t_MKA_bus)MKA_BUS);
        MKA_CP_SetDistributedKI((t_MKA_bus)MKA_BUS,&DISTRIBUTED_KI_3);
        MKA_CP_SetDistributedAN((t_MKA_bus)MKA_BUS,DISTRIBUTED_AN_3);
        MKA_CP_SetUsingReceiveSAs((t_MKA_bus)MKA_BUS, false);

        /* ABANDON Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_2)))
            .Times(1);

        /* RECEIVE Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_CreateSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_3) ))
            .Times(1);
        EXPECT_CALL(mocks, MKA_KAY_EnableReceiveSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_3) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(2);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_3, DISTRIBUTED_AN_3, false, false);
    }

    void FromReadyStateToReceiveState_NewSak(void)
    {
        FromReceiveStateToReadyState();

        MKA_CP_SignalNewSAK((t_MKA_bus)MKA_BUS);
        MKA_CP_SetDistributedKI((t_MKA_bus)MKA_BUS,&DISTRIBUTED_KI_3);
        MKA_CP_SetDistributedAN((t_MKA_bus)MKA_BUS,DISTRIBUTED_AN_3);
        MKA_CP_SetUsingReceiveSAs((t_MKA_bus)MKA_BUS, false);

        /* ABANDON Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_2)))
            .Times(1);

        /* RECEIVE Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_CreateSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_3) ))
            .Times(1);
        EXPECT_CALL(mocks, MKA_KAY_EnableReceiveSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_3) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(2);


        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_3, DISTRIBUTED_AN_3, false, false);
    }

    void FromReceiveStateToReadyState(void)
    {
        FromReceiveStateToReceivingState();

        MKA_CP_SetElectedSelf((t_MKA_bus)MKA_BUS, false);

        /* READY Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_SignalNewInfo(MKA_BUS))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, false, true);
    }

    void FromReadyStateToTransmitState(void)
    {
        FromReceiveStateToReadyState();

        MKA_CP_SetServerTransmitting((t_MKA_bus)MKA_BUS, true);
        MKA_CP_SetUsingTransmitSA((t_MKA_bus)MKA_BUS,false);

        /* TRANSMIT Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_EnableTransmitSA(MKA_BUS, KICompare(&DISTRIBUTED_KI_2) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, true, true);
    }

    void FromReceivingStateToTransmitState_AllReceiving(void)
    {
        FromReceiveStateToReceivingState();

        MKA_CP_SetAllReceiving((t_MKA_bus)MKA_BUS, true);
        MKA_CP_SetUsingTransmitSA((t_MKA_bus)MKA_BUS, false);

        /* TRANSMIT Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_EnableTransmitSA(MKA_BUS, KICompare(&DISTRIBUTED_KI_2) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, true, true);
    }

    void FromReceivingStateToTransmitState_TransmitWhen(void)
    {
        FromReceiveStateToReceivingState();

        MKA_CP_SetAllReceiving((t_MKA_bus)MKA_BUS, false);
        MKA_CP_SetUsingTransmitSA((t_MKA_bus)MKA_BUS, false);
        mka_tick_time_ms += MKA_active_global_config->life_time;

        /* TRANSMIT Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_EnableTransmitSA(MKA_BUS, KICompare(&DISTRIBUTED_KI_2) ))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, true, true);
    }

    void FromTransmitStateToTransmittingState(void)
    {
        FromReceivingStateToTransmitState_TransmitWhen();

        MKA_CP_SetUsingTransmitSA((t_MKA_bus)MKA_BUS, true);

        /* TRANSMITTING Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_SignalNewInfo(MKA_BUS))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, false, true);
        EXPECT_LAT_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, true, true);
    }

    void FromTransmittingStateToRetireState_RetireWhen(void)
    {
        FromTransmitStateToTransmittingState();

        mka_tick_time_ms += MKA_active_global_config->sak_retire_time;

        /* RETIRE Entry State Calls */
        EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_1)))
            .Times(1);

        /* Set interfaces calls */
        test_secy_config_1.protect_frames = PROTECT_FRAMES;
        test_secy_config_1.replay_protect = REPLAY_PROTECT;
        test_secy_config_1.replay_window = REPLAY_WINDOW;
        test_secy_config_1.validate_frames = VALIDATE_FRAMES;
        test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
        test_secy_config_1.controlled_port_enabled = true;
        EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
            .Times(1);

        MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

        EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, true, true);
        EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
    }
};

struct Test_MKA_CP_Init : public Test_MKA_CP_Base {
};

TEST_F(Test_MKA_CP_Init, CallCPInit_and_ReachINITState)
{
    FromFSMInitToINITState();
}

struct Test_MKA_CP_MainFunction : public Test_MKA_CP_Base {
};

/*************************** INIT STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInINITState_WhenPortEnabledIsFalse_ThenDoNothingAndRemainInINITState)
{
    FromFSMInitToINITState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInCHANGEState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromFSMInitToChangeState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInALLOWEDState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromChangeStateToAllowedState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);
    MKA_CP_ConnectUnauthenticated((t_MKA_bus)MKA_BUS);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInAUTHENTICATEDState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromChangeStateToAllowedState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);
    MKA_CP_ConnectAuthenticated((t_MKA_bus)MKA_BUS);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInSECUREDState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromChangeStateToSecuredState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);
    MKA_CP_ConnectSecure((t_MKA_bus)MKA_BUS);

    ExpectedCallsEntryToINIT(); 
    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRECEIVEState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromSecuredStateToReceiveState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRECEIVINGState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromReceiveStateToReceivingState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInTRANSMITState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    PAEKeyServer_FromReceiveStateToTransmitState_ControlledPortDisabled();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInTRANSMITTINGState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromTransmitStateToTransmittingState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRETIREState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromTransmitStateToRetireState_ORxFalse();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInREADYState_WhenPortEnabledIsFalse_ThenTransitionToINITState)
{
    FromReceiveStateToReadyState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, false);

    ExpectedCallsEntryToINIT();

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);
}

/*************************** CHANGE STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInINITState_WhenPortEnabledIsTrue_ThenTransitionToCHANGEState)
{
    FromFSMInitToChangeState();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInALLOWEDState_WhenConnectChanges_ThenTransitionToCHANGEState)
{
    FromChangeStateToAllowedState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectPending((t_MKA_bus)MKA_BUS);

    /* Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);

    /* portValid EVENT */
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = false;
    test_secy_config_1.replay_protect = false;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = MKA_VALIDATE_CHECKED;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInAUTHENTICATEDState_WhenConnectChanges_ThenTransitionToCHANGEState)
{
    FromChangeStateToAuthenticatedState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectPending((t_MKA_bus)MKA_BUS);

    /* Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);

    /* portValid EVENT */
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = false;
    test_secy_config_1.replay_protect = false;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = MKA_VALIDATE_CHECKED;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInSECUREDState_WhenConnectChanges_ThenTransitionToCHANGEState)
{
    FromChangeStateToSecuredState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectPending((t_MKA_bus)MKA_BUS);

    /* Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);

    /* portValid EVENT */
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = PROTECT_FRAMES;
    test_secy_config_1.replay_protect = REPLAY_PROTECT;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = VALIDATE_FRAMES;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInTRANSMITTINGState_WhenConnectChanges_ThenTransitionToCHANGEStateViaRETIREState)
{
    FromTransmitStateToTransmittingState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectPending((t_MKA_bus)MKA_BUS);

    /* RETIRE Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_1)))
        .Times(1);

    /* CHANGE Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(1);
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_2)))
        .Times(1);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = PROTECT_FRAMES;
    test_secy_config_1.replay_protect = REPLAY_PROTECT;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = VALIDATE_FRAMES;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = true;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_2, DISTRIBUTED_AN_2, true, true);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    test_secy_config_2.protect_frames = PROTECT_FRAMES;
    test_secy_config_2.replay_protect = REPLAY_PROTECT;
    test_secy_config_2.replay_window = REPLAY_WINDOW;
    test_secy_config_2.validate_frames = VALIDATE_FRAMES;
    test_secy_config_2.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_2.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_2.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_2)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRECEIVINGState_WhenConnectChanges_ThenTransitionToCHANGEStateViaABANDONAndRETIREState)
{
    FromReceiveStateToReceivingState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectPending((t_MKA_bus)MKA_BUS);

    /* ABANDON Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_2)))
        .Times(1);

    /* RETIRE Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_1)))
        .Times(1);

    /* CHANGE Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = PROTECT_FRAMES;
    test_secy_config_1.replay_protect = REPLAY_PROTECT;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = VALIDATE_FRAMES;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = true;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(2);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    test_secy_config_2.protect_frames = PROTECT_FRAMES;
    test_secy_config_2.replay_protect = REPLAY_PROTECT;
    test_secy_config_2.replay_window = REPLAY_WINDOW;
    test_secy_config_2.validate_frames = VALIDATE_FRAMES;
    test_secy_config_2.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_2.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_2.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_2)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInREADYState_WhenConnectChanges_ThenTransitionToCHANGEStateViaABANDONAndRETIREState)
{
    FromReceiveStateToReadyState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectPending((t_MKA_bus)MKA_BUS);

    /* ABANDON Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_2)))
        .Times(1);

    /* RETIRE Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&DISTRIBUTED_KI_1)))
        .Times(1);

    /* CHANGE Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = PROTECT_FRAMES;
    test_secy_config_1.replay_protect = REPLAY_PROTECT;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = VALIDATE_FRAMES;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = true;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(2);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, DISTRIBUTED_KI_1, DISTRIBUTED_AN_1, true, true);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    test_secy_config_2.protect_frames = PROTECT_FRAMES;
    test_secy_config_2.replay_protect = REPLAY_PROTECT;
    test_secy_config_2.replay_window = REPLAY_WINDOW;
    test_secy_config_2.validate_frames = VALIDATE_FRAMES;
    test_secy_config_2.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_2.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_2.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_2)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

/*************************** ALLOWED STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInCHANGEState_WhenConnectIsUnauthenticated_ThenTransitionToALLOWEDState)
{
    FromChangeStateToAllowedState();
}

/*************************** AUTHENTICATED STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInCHANGEState_WhenConnectIsAuthenticated_ThenTransitionToAUTHENTICATEDState)
{
    FromChangeStateToAuthenticatedState();
}

/*************************** SECURED STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInCHANGEState_WhenConnectIsSecure_ThenTransitionToSECUREDState)
{
    FromChangeStateToSecuredState();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInSECUREDState_WhenChgdServerIsSet_ThenTransitionToCHANGEStateAndSECUREDStateAgain)
{
    FromChangeStateToSecuredState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectSecure((t_MKA_bus)MKA_BUS);
    MKA_CP_SignalChgdServer((t_MKA_bus)MKA_BUS);

    /* Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_VALID))
        .Times(1);

    /* GetKAY info */
    EXPECT_CALL(mocks, MKA_KAY_GetProtectFrames(MKA_BUS))
        .WillOnce(Return(PROTECT_FRAMES));
    EXPECT_CALL(mocks, MKA_KAY_GetValidateFrames(MKA_BUS))
        .WillOnce(Return(VALIDATE_FRAMES));
    EXPECT_CALL(mocks, MKA_KAY_GetReplayProtect(MKA_BUS))
        .WillOnce(Return(REPLAY_PROTECT));
    EXPECT_CALL(mocks, MKA_KAY_GetReplayWindow(MKA_BUS))
        .WillOnce(Return(REPLAY_WINDOW));

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = PROTECT_FRAMES;
    test_secy_config_1.replay_protect = REPLAY_PROTECT;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = VALIDATE_FRAMES;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(2);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInSECUREDState_WhenCipherSuiteChanges_ThenTransitionToCHANGEStateAndSECUREDStateAgain)
{
    FromChangeStateToSecuredState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectSecure((t_MKA_bus)MKA_BUS);
    MKA_CP_SetCipherSuite((t_MKA_bus)MKA_BUS, MKA_CS_ID_GCM_AES_256);

    /* Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_VALID))
        .Times(1);

    /* GetKAY info */
    EXPECT_CALL(mocks, MKA_KAY_GetProtectFrames(MKA_BUS))
        .WillOnce(Return(PROTECT_FRAMES));
    EXPECT_CALL(mocks, MKA_KAY_GetValidateFrames(MKA_BUS))
        .WillOnce(Return(VALIDATE_FRAMES));
    EXPECT_CALL(mocks, MKA_KAY_GetReplayProtect(MKA_BUS))
        .WillOnce(Return(REPLAY_PROTECT));
    EXPECT_CALL(mocks, MKA_KAY_GetReplayWindow(MKA_BUS))
        .WillOnce(Return(REPLAY_WINDOW));

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = PROTECT_FRAMES;
    test_secy_config_1.replay_protect = REPLAY_PROTECT;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = VALIDATE_FRAMES;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    test_secy_config_2.protect_frames = PROTECT_FRAMES;
    test_secy_config_2.replay_protect = REPLAY_PROTECT;
    test_secy_config_2.replay_window = REPLAY_WINDOW;
    test_secy_config_2.validate_frames = VALIDATE_FRAMES;
    test_secy_config_2.current_cipher_suite = MKA_CS_ID_GCM_AES_256;
    test_secy_config_2.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_2.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_2)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInSECUREDState_WhenCipherOffsetChanges_ThenTransitionToCHANGEStateAndSECUREDStateAgain)
{
    FromChangeStateToSecuredState();

    MKA_CP_SetPortEnabled((t_MKA_bus)MKA_BUS, true);
    MKA_CP_ConnectSecure((t_MKA_bus)MKA_BUS);
    MKA_CP_SetCipherOffset((t_MKA_bus)MKA_BUS, MKA_CONFIDENTIALITY_OFFSET_30);

    /* Entry State Calls */
    EXPECT_CALL(mocks, MKA_KAY_DeleteSAs(MKA_BUS, KICompare(&ZERO_KI)))
        .Times(2);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_NOT_VALID))
        .Times(1);
    EXPECT_CALL(mocks, event_action(MKA_BUS, MKA_EVENT_PORT_VALID))
        .Times(1);

    /* GetKAY info */
    EXPECT_CALL(mocks, MKA_KAY_GetProtectFrames(MKA_BUS))
        .WillOnce(Return(PROTECT_FRAMES));
    EXPECT_CALL(mocks, MKA_KAY_GetValidateFrames(MKA_BUS))
        .WillOnce(Return(VALIDATE_FRAMES));
    EXPECT_CALL(mocks, MKA_KAY_GetReplayProtect(MKA_BUS))
        .WillOnce(Return(REPLAY_PROTECT));
    EXPECT_CALL(mocks, MKA_KAY_GetReplayWindow(MKA_BUS))
        .WillOnce(Return(REPLAY_WINDOW));

    /* Set interfaces calls */
    test_secy_config_1.protect_frames = PROTECT_FRAMES;
    test_secy_config_1.replay_protect = REPLAY_PROTECT;
    test_secy_config_1.replay_window = REPLAY_WINDOW;
    test_secy_config_1.validate_frames = VALIDATE_FRAMES;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_0;
    test_secy_config_1.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_1)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);

    test_secy_config_2.protect_frames = PROTECT_FRAMES;
    test_secy_config_2.replay_protect = REPLAY_PROTECT;
    test_secy_config_2.replay_window = REPLAY_WINDOW;
    test_secy_config_2.validate_frames = VALIDATE_FRAMES;
    test_secy_config_2.current_cipher_suite = MKA_CS_ID_GCM_AES_128;
    test_secy_config_2.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_30;
    test_secy_config_2.controlled_port_enabled = false;
    EXPECT_CALL(mocks, MKA_SECY_UpdateConfiguration(MKA_BUS, CompareSecYConfig(&test_secy_config_2)))
        .Times(1);

    MKA_CP_MainFunctionTick((t_MKA_bus)MKA_BUS);

    EXPECT_OLD_SA(MKA_BUS, ZERO_KI, 0, false, false);
    EXPECT_LAT_SA(MKA_BUS, ZERO_KI, 0, false, false);
}

/*************************** RECEIVE STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInSECUREDState_WhenNewSAKIsTrue_ThenTransitionToRECEIVEState)
{
    FromSecuredStateToReceiveState();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRETIREState_WhenNewSAKIsTrue_ThenTransitionToRECEIVEState)
{
    FromRetireStateToReceiveState_NewSak();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRECEIVINGState_WhenNewSAKIsTrue_ThenTransitionToRECEIVEStateViaABANDONState)
{
    FromReceivingStateToReceiveState_NewSak();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInREADYState_WhenNewSAKIsTrue_ThenTransitionToRECEIVEStateViaABANDONState)
{
    FromReadyStateToReceiveState_NewSak();
}

/*************************** RECEIVING STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInRECEIVEState_WhenUsingReceiveSAsIsTrue_ThenTransitionToRECEIVINGState)
{
    FromReceiveStateToReceivingState();
}

/*************************** READY STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenPAEIsNotKeyServerAndCPInRECEIVEState_WhenControlledPortIsDisabled_ThenTransitionToREADYState)
{
    FromReceiveStateToReadyState();
}

/*************************** TRANSMIT STATE KEY SERVER (electedSelf) ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenPAEIsKeyServerAndCPInRECEIVEState_WhenUsingReceiveSAsIsTrueAndControllerPortEnabledIsFalse_ThenTransitionToTRANSMITStateViaRECEIVINGState)
{
    PAEKeyServer_FromReceiveStateToTransmitState_ControlledPortDisabled();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRECEIVINGState_WhenAllReceivingIsTrue_ThenTransitionToTRANSMITState)
{
    FromReceivingStateToTransmitState_AllReceiving();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInRECEIVINGState_WhenTransmitWhenZero_ThenTransitionToTRANSMITState)
{
    FromReceivingStateToTransmitState_TransmitWhen();
}

/*************************** TRANSMIT STATE NOT KEY SERVER (!electedSelf) ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenPAEIsNotKeyServerAndCPInRECEIVEState_WhenUsingReceiveSAsIsTrueAndControllerPortEnabledIsFalse_ThenTransitionToTRANSMITStateViaRECEIVINGAndREADYStates)
{
    PAENOKeyServer_FromReceiveStateToTransmitState_ControlledPortDisabled();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInREADYState_WhenServerTransmittingIsTrue_ThenTransitionToTRANSMIT)
{
    FromReadyStateToTransmitState();
}

/*************************** TRANSMITTING STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInTRANSMITState_WhenUsingUsingTransmitSAIsTrue_ThenTransitionToTRANSMITTINGState)
{
    FromTransmitStateToTransmittingState();
}

/*************************** RETIRE STATE ***************************/
TEST_F(Test_MKA_CP_MainFunction, GivenCPInTRANSMITState_WhenUsingUsingTransmitSAIsTrueAndORxIsFalse_ThenTransitionToRETIREState)
{
    FromTransmitStateToRetireState_ORxFalse();
}

TEST_F(Test_MKA_CP_MainFunction, GivenCPInTRANSMITTINGState_WhenRetireWhenZero_ThenTransitionToRETIREState)
{
    FromTransmittingStateToRetireState_RetireWhen();
}


struct Test_MKA_CP_GetProtectFrames : public Test_MKA_CP_Base {
};

TEST_F(Test_MKA_CP_GetProtectFrames, Get_Protect_Frames)
{
    FromTransmitStateToRetireState_ORxFalse();
    ASSERT_TRUE(MKA_CP_GetProtectFrames(MKA_BUS));
}

struct Test_MKA_CP_GetValidateFrames : public Test_MKA_CP_Base {
};

TEST_F(Test_MKA_CP_GetValidateFrames, Get_Validate_Frames)
{
    FromTransmitStateToRetireState_ORxFalse();
    ASSERT_EQ(MKA_CP_GetValidateFrames(MKA_BUS), VALIDATE_FRAMES);
}
