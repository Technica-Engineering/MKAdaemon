/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: ut_mka_secy.cpp
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

#include "mka_secy.h"

typedef struct {
    t_MKA_key SAK;
    t_MKA_key HASH;
    t_MKA_key SALT;
    t_MKA_ki key_identifier;
    bool transmits;
    bool receives;
    bool in_use_tx;
    bool in_use_rx;
    uint32_t installation_time;
} t_MKA_data_key;

#define MKA_BUS 0

extern "C" void mock_assertion_action(void){ }
extern "C" void mock_print(char const* text, unsigned long length)
{
    printf("%s", text);
}

uint32_t mka_tick_time_ms;
constexpr uint32_t TIME_INCR = 50;
static t_MKA_SECY_config test_secy_config_1;
static t_MKA_sci test_sci_1;
static t_MKA_key test_sak;
static t_MKA_key test_hash;
static t_MKA_key test_salt;
static t_MKA_ki test_ki;

t_MKA_global_config MKA_test_global_config = {
    .hello_time = 2000U,
    .bounded_hello_time = 500U,
    .life_time = 6000U,
    .sak_retire_time = 3000U,
    .hello_rampup = { 100U, 200U, 400U, 800U, 800U },
    .hello_rampup_number = 5U,
    .transmit_empty_dist_sak = true,
    .transmit_empty_sak_use = true,
    .transmit_null_xpn = true,
    .secy_polling_ms = 5U
};

t_MKA_bus_config MKA_test_bus_config = {
    .enable = true,
    .port_capabilities = {0},
    .port_name = "dummy",
    .port_number = 0,
    .controlled_port_name = "dummy",
    .kay = {
        .enable = true,
        .actor_priority = 128,
        .actor_role = MKA_ROLE_AUTO,
        .macsec_capable = MKA_MACSEC_INT_CONF_0_30_50,
        .macsec_desired = true,
        .replay_protect = false,
        .replay_protect_wnd = 0,
        .delay_protect = true,
        .pcpt_activation = MKA_ACTIVATE_ONOPERUP
    },
    .logon_nid = {
        .unauth_allowed = MKA_UNAUTH_IMMEDIATE,
        .unsecure_allowed = MKA_UNSECURE_IMMEDIATE
    },
    .logon_process = {
        .logon = false
    },
    .impl = {
        .phy_driver = {
            &MKA_PHY_UpdateSecY,
            &MKA_PHY_InitRxSC,
            &MKA_PHY_DeinitRxSC,
            &MKA_PHY_AddTxSA,
            &MKA_PHY_UpdateTxSA,
            &MKA_PHY_DeleteTxSA,
            &MKA_PHY_AddRxSA,
            &MKA_PHY_UpdateRxSA,
            &MKA_PHY_DeleteRxSA,
            &MKA_PHY_GetTxSANextPN,
            &MKA_PHY_GetMacSecStats
        },
        .key_mng = { NULL },
        .cipher_preference = {0ULL},
        .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
        .mode = MKA_MACSEC_SOFTWARE,
        .mc_uart = NULL,
        .phy_settings = { 0 },
        .intf_mode = MKA_INTF_MODE_STATIC,
    }
};

t_MKA_global_config const* MKA_active_global_config = &MKA_test_global_config;
t_MKA_bus_config const* MKA_active_buses_config = &MKA_test_bus_config;

ACTION_P(SetHASH, varPtr) {
    memcpy(arg2, varPtr, 16);
}

ACTION_P(SetStatsTxSecY, varPtr) {
    memcpy(arg1, varPtr, sizeof(t_MKA_stats_transmit_secy));
}

ACTION_P(SetStatsRxSecY, varPtr) {
    memcpy(arg2, varPtr, sizeof(t_MKA_stats_receive_secy));
}

ACTION_P(SetStatsTxSC, varPtr) {
    memcpy(arg3, varPtr, sizeof(t_MKA_stats_transmit_sc));
}

ACTION_P(SetStatsRxSC, varPtr) {
    memcpy(arg4, varPtr, sizeof(t_MKA_stats_receive_sc));
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

MATCHER_P(CompareSci, varPtr, "Matcher to compare t_MKA_sci") {
    if (memcmp(arg,varPtr,sizeof(t_MKA_sci)) != 0) {
        return false;
    }
    return true;
}

MATCHER_P(CompareSAK, varPtr, "Matcher to compare t_MKA_key") {
    if (memcmp(arg,varPtr,sizeof(t_MKA_key)) != 0) {
        return false;
    }
    return true;
}

MATCHER_P(CompareHASH, varPtr, "Matcher to compare HASH key") {
    if (memcmp(arg->key,varPtr->key,16) != 0) {
        if(arg->length != 16) {
            return false;
        }
    }
    return true;
}

MATCHER_P(CompareSALT, varPtr, "Matcher to compare SALT") {
    if (memcmp(arg->key,varPtr->key,12) != 0) {
        if(arg->length != 12) {
            return false;
        }
    }
    return true;
}

MATCHER_P(CompareKI, varPtr, "Matcher to compare t_MKA_ki") {
    if (memcmp(arg,varPtr,sizeof(t_MKA_ki)) != 0) {
        return false;
    }
    return true;
}

class Test_MKA_SECY_Base : public ::testing::Test {
   protected:
   public:
    Mock::Mocks mocks;

    virtual void SetUp(void)
    {
        mka_tick_time_ms = 15000;

        test_secy_config_1.protect_frames = false;
        test_secy_config_1.replay_protect = false;
        test_secy_config_1.replay_window = 0;
        test_secy_config_1.validate_frames = MKA_VALIDATE_NULL;
        test_secy_config_1.current_cipher_suite = MKA_CS_NULL;
        test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_NONE;
        test_secy_config_1.controlled_port_enabled = false;

        memset(&test_sci_1, 0xFF, sizeof(t_MKA_sci));
        memset(&test_sak, 0xFF, sizeof(t_MKA_key));
        memset(&test_hash, 0xFF, sizeof(t_MKA_key));
        memset(&test_salt, 0xFF, sizeof(t_MKA_key));
        memset(&test_ki, 0xFF, sizeof(t_MKA_ki));

        MKA_SECY_Init(MKA_BUS);
    }

    virtual void TearDown(void)
    {
    }

    t_MKA_transmit_sc* CreateTransmitSC(uint32_t timestamp)
    {
        for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
            test_sci_1.addr[i] = i;
        }
        test_sci_1.port = 0x1234;

        EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
            .WillOnce(Return(MKA_OK));

        t_MKA_transmit_sc* sc_pointer = MKA_SECY_CreateTransmitSC(MKA_BUS, &test_sci_1);

        EXPECT_TRUE(0==memcmp(&test_sci_1, &sc_pointer->sci, sizeof(t_MKA_sci)));
        EXPECT_FALSE(sc_pointer->transmitting);
        EXPECT_EQ(timestamp, sc_pointer->created_time);
        EXPECT_EQ(timestamp, sc_pointer->started_time);
        EXPECT_EQ(timestamp, sc_pointer->stopped_time);
        EXPECT_EQ(0U, sc_pointer->sc_stats->out_pkts_protected);
        EXPECT_EQ(0U, sc_pointer->sc_stats->out_pkts_encrypted);

        return sc_pointer;
    }

    t_MKA_receive_sc* CreateReceiveSC(uint32_t timestamp)
    {
        for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
            test_sci_1.addr[i] = i;
        }
        test_sci_1.port = 0x1234;

        EXPECT_CALL(mocks, MKA_PHY_InitRxSC(MKA_BUS,CompareSci(&test_sci_1)))
            .WillOnce(Return(MKA_OK));

        t_MKA_receive_sc* sc_pointer = MKA_SECY_CreateReceiveSC(MKA_BUS, &test_sci_1);

        EXPECT_TRUE(0==memcmp(&test_sci_1, &sc_pointer->sci, sizeof(t_MKA_sci)));
        EXPECT_FALSE(sc_pointer->receiving);
        EXPECT_EQ(timestamp, sc_pointer->created_time);
        EXPECT_EQ(timestamp, sc_pointer->started_time);
        EXPECT_EQ(timestamp, sc_pointer->stopped_time);
        EXPECT_EQ(0U, sc_pointer->sc_stats->in_pkts_ok);
        EXPECT_EQ(0U, sc_pointer->sc_stats->in_pkts_unchecked);
        EXPECT_EQ(0U, sc_pointer->sc_stats->in_pkts_delayed);
        EXPECT_EQ(0U, sc_pointer->sc_stats->in_pkts_late);
        EXPECT_EQ(0U, sc_pointer->sc_stats->in_pkts_invalid);
        EXPECT_EQ(0U, sc_pointer->sc_stats->in_pkts_not_valid);

        return sc_pointer;
    }

    void* InstallGoodKey(bool transmits, bool receives)
    {
        for(uint8_t i = 0; i <MKA_KEY_MAX;i++) {
            test_sak.key[i] = i;
        }
        test_sak.length = MKA_KEY_MAX;

        for(uint8_t i = 0; i <16;i++) {
            test_hash.key[i] = i+0x20;
        }
        test_hash.length = 16;

        for(uint8_t i = 0; i < MKA_MI_LENGTH; i++) {
            test_ki.mi[i] = i;
        }
        test_ki.kn = 0x23898923;

        for(uint8_t i = 0; i < 8; i++) {
            test_salt.key[i] = i;
        }
        test_salt.key[8] = test_ki.mi[8] ^ (uint8_t)((test_ki.kn & 0xFF000000U) >> 24U);
        test_salt.key[9] = test_ki.mi[9] ^ (uint8_t)((test_ki.kn & 0x00FF0000U) >> 16U);
        test_salt.key[10]= test_ki.mi[10]^ (uint8_t)((test_ki.kn & 0x0000FF00U) >> 8U);
        test_salt.key[11]= test_ki.mi[11]^ (uint8_t) (test_ki.kn & 0x000000FFU);
        test_salt.length = 12;

        EXPECT_CALL(mocks, aes_encrypt_init(test_sak.key,test_sak.length))
            .WillOnce(Return((void*)1));
        EXPECT_CALL(mocks, aes_encrypt((void*)1,_,_))
            .WillOnce(DoAll(SetHASH(test_hash.key),  Return(0)));
        EXPECT_CALL(mocks, aes_encrypt_deinit(_))
            .Times(1);

        return MKA_SECY_InstallKey(MKA_BUS, &test_sak, &test_ki, transmits, receives);
    }

    void* InstallBadKeyWrongSAK(void)
    {
        for(uint8_t i = 0; i < MKA_MI_LENGTH; i++) {
            test_ki.mi[i] = i;
        }
        test_ki.kn = 0x23898923;

        return MKA_SECY_InstallKey(MKA_BUS, NULL, &test_ki, true, true);
    }

    void* InstallBadKeyWrongKI(void)
    {
        for(uint8_t i = 0; i <MKA_KEY_MAX;i++) {
            test_sak.key[i] = i;
        }
        test_sak.length = MKA_KEY_MAX;

        return MKA_SECY_InstallKey(MKA_BUS, &test_sak, NULL, true, true);
    }

    void* InstallBadKeyErrorCrypto1(void)
    {
        for(uint8_t i = 0; i <MKA_KEY_MAX;i++) {
            test_sak.key[i] = i;
        }
        test_sak.length = MKA_KEY_MAX;

        for(uint8_t i = 0; i <16;i++) {
            test_hash.key[i] = i+0x20;
        }
        test_hash.length = 16;

        for(uint8_t i = 0; i < MKA_MI_LENGTH; i++) {
            test_ki.mi[i] = i;
        }
        test_ki.kn = 0x23898923;

        for(uint8_t i = 0; i < 8; i++) {
            test_salt.key[i] = i;
        }
        test_salt.key[8] = test_ki.mi[8] ^ (uint8_t)((test_ki.kn & 0xFF000000U) >> 24U);
        test_salt.key[9] = test_ki.mi[9] ^ (uint8_t)((test_ki.kn & 0x00FF0000U) >> 16U);
        test_salt.key[10]= test_ki.mi[10]^ (uint8_t)((test_ki.kn & 0x0000FF00U) >> 8U);
        test_salt.key[11]= test_ki.mi[11]^ (uint8_t) (test_ki.kn & 0x000000FFU);
        test_salt.length = 12;

        EXPECT_CALL(mocks, aes_encrypt_init(test_sak.key,test_sak.length))
            .WillOnce(Return((void *)0));
        EXPECT_CALL(mocks, aes_encrypt(_,_,_))
            .Times(0);
        EXPECT_CALL(mocks, aes_encrypt_deinit(_))
            .Times(0);

        return MKA_SECY_InstallKey(MKA_BUS, &test_sak, &test_ki, true, true);
    }

    void* InstallBadKeyErrorCrypto2(void)
    {
        for(uint8_t i = 0; i <MKA_KEY_MAX;i++) {
            test_sak.key[i] = i;
        }
        test_sak.length = MKA_KEY_MAX;

        for(uint8_t i = 0; i <16;i++) {
            test_hash.key[i] = i+0x20;
        }
        test_hash.length = 16;

        for(uint8_t i = 0; i < MKA_MI_LENGTH; i++) {
            test_ki.mi[i] = i;
        }
        test_ki.kn = 0x23898923;

        for(uint8_t i = 0; i < 8; i++) {
            test_salt.key[i] = i;
        }
        test_salt.key[8] = test_ki.mi[8] ^ (uint8_t)((test_ki.kn & 0xFF000000U) >> 24U);
        test_salt.key[9] = test_ki.mi[9] ^ (uint8_t)((test_ki.kn & 0x00FF0000U) >> 16U);
        test_salt.key[10]= test_ki.mi[10]^ (uint8_t)((test_ki.kn & 0x0000FF00U) >> 8U);
        test_salt.key[11]= test_ki.mi[11]^ (uint8_t) (test_ki.kn & 0x000000FFU);
        test_salt.length = 12;

        EXPECT_CALL(mocks, aes_encrypt_init(test_sak.key,test_sak.length))
            .WillOnce(Return((void*)1));
        EXPECT_CALL(mocks, aes_encrypt((void*)1,_,_))
            .WillOnce(DoAll(SetHASH(test_hash.key),  Return(-1)));
        EXPECT_CALL(mocks, aes_encrypt_deinit(_))
            .Times(1);

        return MKA_SECY_InstallKey(MKA_BUS, &test_sak, &test_ki, true, true);
    }

    t_MKA_transmit_sa* CreateTransmitSA(uint32_t timestamp, void* key_pointer)
    {
        constexpr uint8_t test_AN = 2;
        constexpr t_MKA_pn test_nextPN = 0x12459874;
        constexpr t_MKA_ssci test_ssci = 0x54332211;
        constexpr t_MKA_confidentiality_offset test_co = MKA_CONFIDENTIALITY_OFFSET_50;

        EXPECT_CALL(mocks, MKA_PHY_AddTxSA(MKA_BUS,test_AN, test_nextPN, 0, CompareSAK(&test_sak), CompareHASH(&test_hash), CompareSALT(&test_salt), CompareKI(&test_ki), false))
            .WillOnce(Return(MKA_OK));
        
        t_MKA_transmit_sa* sa_pointer = MKA_SECY_CreateTransmitSA(MKA_BUS, test_AN, test_nextPN, test_ssci, test_co, key_pointer);

        EXPECT_FALSE(sa_pointer->in_use);
        EXPECT_EQ(sa_pointer->ssci, test_ssci);
        EXPECT_EQ(sa_pointer->confidentiality, test_co);
        EXPECT_EQ(sa_pointer->next_pn, test_nextPN);
        EXPECT_EQ(timestamp, sa_pointer->created_time);
        EXPECT_EQ(timestamp, sa_pointer->started_time);
        EXPECT_EQ(timestamp, sa_pointer->stopped_time);
        EXPECT_EQ(sa_pointer->an, test_AN);
        EXPECT_EQ(sa_pointer->data_key, key_pointer);
        EXPECT_FALSE(sa_pointer->enable_transmit);

        return sa_pointer;
    }

    t_MKA_receive_sa* CreateReceiveSA(uint32_t timestamp, void* key_pointer)
    {
        constexpr uint8_t test_AN = 2;
        constexpr t_MKA_pn test_lowestPN = 0x87541269;
        constexpr t_MKA_ssci test_ssci = 0x11223345;

        EXPECT_CALL(mocks, MKA_PHY_AddRxSA(MKA_BUS,test_AN, test_lowestPN, 0, CompareSAK(&test_sak), CompareHASH(&test_hash), CompareSALT(&test_salt), CompareKI(&test_ki), false))
            .WillOnce(Return(MKA_OK));
        
        t_MKA_receive_sa* sa_pointer = MKA_SECY_CreateReceiveSA(MKA_BUS, test_AN, test_lowestPN, test_ssci, key_pointer);

        EXPECT_FALSE(sa_pointer->in_use);
        EXPECT_EQ(sa_pointer->ssci, test_ssci);
        EXPECT_EQ(sa_pointer->next_pn, test_lowestPN);
        EXPECT_EQ(sa_pointer->lowest_pn, test_lowestPN);
        EXPECT_EQ(timestamp, sa_pointer->created_time);
        EXPECT_EQ(timestamp, sa_pointer->started_time);
        EXPECT_EQ(timestamp, sa_pointer->stopped_time);
        EXPECT_EQ(sa_pointer->an, test_AN);
        EXPECT_EQ(sa_pointer->data_key, key_pointer);
        EXPECT_FALSE(sa_pointer->enable_receive);

        return sa_pointer;
    }
};

struct Test_MKA_SECY_UpdateConfiguration : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_UpdateConfiguration, Test_UpdateConfiguration_NullPointer)
{
    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,_,_))
        .Times(0);

    MKA_SECY_UpdateConfiguration(MKA_BUS, NULL);
}

TEST_F(Test_MKA_SECY_UpdateConfiguration, Test_UpdateConfiguration_NewConfig)
{
    test_secy_config_1.protect_frames = true;
    test_secy_config_1.replay_protect = true;
    test_secy_config_1.replay_window = 4;
    test_secy_config_1.validate_frames = MKA_VALIDATE_STRICT;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_256;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_30;
    test_secy_config_1.controlled_port_enabled = true;

    memset(&test_sci_1, 0xFF, sizeof(t_MKA_sci));

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);
}

TEST_F(Test_MKA_SECY_UpdateConfiguration, Test_UpdateConfiguration_RepeatConfigAndDoNothing)
{
    test_secy_config_1.protect_frames = true;
    test_secy_config_1.replay_protect = true;
    test_secy_config_1.replay_window = 4;
    test_secy_config_1.validate_frames = MKA_VALIDATE_STRICT;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_256;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_30;
    test_secy_config_1.controlled_port_enabled = true;

    memset(&test_sci_1, 0xFF, sizeof(t_MKA_sci));

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);
    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);
    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);
    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);
    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);
}

struct Test_MKA_SECY_TransmitSC : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_TransmitSC, Test_CreateTXSC_SCINullPointer)
{
    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,_,_))
        .Times(0);

    t_MKA_transmit_sc* sc_pointer = MKA_SECY_CreateTransmitSC(MKA_BUS, NULL);

    EXPECT_EQ(NULL, sc_pointer);
}

TEST_F(Test_MKA_SECY_TransmitSC, Test_CreateTXSC_DriverFails)
{
    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = MKA_L2_ADDR_SIZE - i;
    }
    test_sci_1.port = 0x4321;

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,_,_))
        .WillOnce(Return(MKA_NOT_OK));

    t_MKA_transmit_sc* sc_pointer = MKA_SECY_CreateTransmitSC(MKA_BUS, &test_sci_1);

    EXPECT_EQ(NULL, sc_pointer);
}

TEST_F(Test_MKA_SECY_TransmitSC, Test_CreateFirstTXSCOK_CreateSecondTXSCFail)
{
    CreateTransmitSC(mka_tick_time_ms);

    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = MKA_L2_ADDR_SIZE - i;
    }
    test_sci_1.port = 0x4321;

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,_,_))
        .Times(0);

    t_MKA_transmit_sc* sc_pointer = MKA_SECY_CreateTransmitSC(MKA_BUS, &test_sci_1);

    EXPECT_EQ(NULL, sc_pointer);
}

TEST_F(Test_MKA_SECY_TransmitSC, Test_DeleteTXSC_CreateTXSCAgain)
{
    t_MKA_transmit_sc* sc_pointer_1 = CreateTransmitSC(mka_tick_time_ms);

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,_,NULL))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_DestroyTransmitSC(MKA_BUS,sc_pointer_1);

    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = 0xFF;
    }
    test_sci_1.port = 0xFFFF;
    EXPECT_TRUE(0==memcmp(&test_sci_1, &sc_pointer_1->sci, sizeof(t_MKA_sci)));
    EXPECT_FALSE(sc_pointer_1->transmitting);
    EXPECT_EQ(0U, sc_pointer_1->created_time);
    EXPECT_EQ(0U, sc_pointer_1->started_time);
    EXPECT_EQ(0U, sc_pointer_1->stopped_time);
    EXPECT_EQ(NULL, sc_pointer_1->sc_stats);

    /********************************************************************/

    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = i+10;
    }
    test_sci_1.port = 0x2143;

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    t_MKA_transmit_sc* sc_pointer_2 = MKA_SECY_CreateTransmitSC(MKA_BUS, &test_sci_1);

    EXPECT_TRUE(0==memcmp(&test_sci_1, &sc_pointer_2->sci, sizeof(t_MKA_sci)));
    EXPECT_FALSE(sc_pointer_2->transmitting);
    EXPECT_EQ(mka_tick_time_ms, sc_pointer_2->created_time);
    EXPECT_EQ(mka_tick_time_ms, sc_pointer_2->started_time);
    EXPECT_EQ(mka_tick_time_ms, sc_pointer_2->stopped_time);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->out_pkts_protected);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->out_pkts_encrypted);
}

TEST_F(Test_MKA_SECY_TransmitSC, Test_DeleteTXSCNull)
{
    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,_,_))
        .Times(0);

    MKA_SECY_DestroyTransmitSC(MKA_BUS,NULL);
}

struct Test_MKA_SECY_ReceiveSC : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_ReceiveSC, Test_CreateRXSC_SCINullPointer)
{
    EXPECT_CALL(mocks, MKA_PHY_InitRxSC(MKA_BUS,_))
        .Times(0);

    t_MKA_receive_sc* sc_pointer = MKA_SECY_CreateReceiveSC(MKA_BUS, NULL);

    EXPECT_EQ(NULL, sc_pointer);
}

TEST_F(Test_MKA_SECY_ReceiveSC, Test_CreateRXSC_DriverFails)
{
    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = MKA_L2_ADDR_SIZE - i;
    }
    test_sci_1.port = 0x4321;

    EXPECT_CALL(mocks, MKA_PHY_InitRxSC(MKA_BUS,_))
        .WillOnce(Return(MKA_NOT_OK));

    t_MKA_receive_sc* sc_pointer = MKA_SECY_CreateReceiveSC(MKA_BUS, &test_sci_1);

    EXPECT_EQ(NULL, sc_pointer);
}

TEST_F(Test_MKA_SECY_ReceiveSC, Test_CreateFirstRXSCOK_CreateSecondRXSCFail)
{
    CreateReceiveSC(mka_tick_time_ms);

    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = MKA_L2_ADDR_SIZE - i;
    }
    test_sci_1.port = 0x4321;

    EXPECT_CALL(mocks, MKA_PHY_InitRxSC(MKA_BUS,_))
        .Times(0);

    t_MKA_receive_sc* sc_pointer = MKA_SECY_CreateReceiveSC(MKA_BUS, &test_sci_1);

    EXPECT_EQ(NULL, sc_pointer);
}

TEST_F(Test_MKA_SECY_ReceiveSC, Test_DeleteRXSC_CreateRXSCAgain)
{
    t_MKA_receive_sc* sc_pointer = CreateReceiveSC(mka_tick_time_ms);

    EXPECT_CALL(mocks, MKA_PHY_DeinitRxSC(MKA_BUS,CompareSci(&sc_pointer->sci)))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_DestroyReceiveSC(MKA_BUS,sc_pointer);

    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = 0xFF;
    }
    test_sci_1.port = 0xFFFF;
    EXPECT_TRUE(0==memcmp(&test_sci_1, &sc_pointer->sci, sizeof(t_MKA_sci)));
    EXPECT_FALSE(sc_pointer->receiving);
    EXPECT_EQ(0U, sc_pointer->created_time);
    EXPECT_EQ(0U, sc_pointer->started_time);
    EXPECT_EQ(0U, sc_pointer->stopped_time);
    EXPECT_EQ(NULL, sc_pointer->sc_stats);

    /********************************************************************/

    mka_tick_time_ms += TIME_INCR;

    for (uint8_t i = 0; i <MKA_L2_ADDR_SIZE; i++) {
        test_sci_1.addr[i] = i+10;
    }
    test_sci_1.port = 0x2143;

    EXPECT_CALL(mocks, MKA_PHY_InitRxSC(MKA_BUS,CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    t_MKA_receive_sc* sc_pointer_2 = MKA_SECY_CreateReceiveSC(MKA_BUS, &test_sci_1);

    EXPECT_TRUE(0==memcmp(&test_sci_1, &sc_pointer_2->sci, sizeof(t_MKA_sci)));
    EXPECT_FALSE(sc_pointer->receiving);
    EXPECT_EQ(mka_tick_time_ms, sc_pointer_2->created_time);
    EXPECT_EQ(mka_tick_time_ms, sc_pointer_2->started_time);
    EXPECT_EQ(mka_tick_time_ms, sc_pointer_2->stopped_time);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->in_pkts_ok);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->in_pkts_unchecked);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->in_pkts_delayed);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->in_pkts_late);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->in_pkts_invalid);
    EXPECT_EQ(0U, sc_pointer_2->sc_stats->in_pkts_not_valid);
}

TEST_F(Test_MKA_SECY_ReceiveSC, Test_DeleteRXSCNull)
{
    EXPECT_CALL(mocks, MKA_PHY_DeinitRxSC(MKA_BUS,_))
        .Times(0);

    MKA_SECY_DestroyReceiveSC(MKA_BUS,NULL);
}

struct Test_MKA_SECY_CreateDestroyTransmitSA : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_CreateDestroyTransmitSA, Test_CreateTXSA_SakNullPointer)
{
    void* key_pointer;
    
    key_pointer = InstallBadKeyWrongSAK();
    EXPECT_CALL(mocks, MKA_PHY_AddTxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_transmit_sa* sa_pointer1 = MKA_SECY_CreateTransmitSA(MKA_BUS, 2, 1, 0U, MKA_CONFIDENTIALITY_OFFSET_30, key_pointer);
    EXPECT_EQ(NULL, sa_pointer1);

    key_pointer = InstallBadKeyWrongKI();
    EXPECT_CALL(mocks, MKA_PHY_AddTxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_transmit_sa* sa_pointer2 = MKA_SECY_CreateTransmitSA(MKA_BUS, 2, 1, 0U, MKA_CONFIDENTIALITY_OFFSET_30, key_pointer);
    EXPECT_EQ(NULL, sa_pointer2);

    key_pointer = InstallBadKeyErrorCrypto1();
    EXPECT_CALL(mocks, MKA_PHY_AddTxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_transmit_sa* sa_pointer3 = MKA_SECY_CreateTransmitSA(MKA_BUS, 2, 1, 0U, MKA_CONFIDENTIALITY_OFFSET_30, key_pointer);
    EXPECT_EQ(NULL, sa_pointer3);

    key_pointer = InstallBadKeyErrorCrypto2();
    EXPECT_CALL(mocks, MKA_PHY_AddTxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_transmit_sa* sa_pointer4 = MKA_SECY_CreateTransmitSA(MKA_BUS, 2, 1, 0U, MKA_CONFIDENTIALITY_OFFSET_30, key_pointer);
    EXPECT_EQ(NULL, sa_pointer4);
}

TEST_F(Test_MKA_SECY_CreateDestroyTransmitSA, Test_CreateTXSA_KeyNotValidForTX)
{
    void* key_pointer = InstallGoodKey(false, true);

    EXPECT_CALL(mocks, MKA_PHY_AddTxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);

    t_MKA_transmit_sa* sa_pointer = MKA_SECY_CreateTransmitSA(MKA_BUS, 2, 1, 0U, MKA_CONFIDENTIALITY_OFFSET_30, key_pointer);

    EXPECT_EQ(NULL, sa_pointer);
}

TEST_F(Test_MKA_SECY_CreateDestroyTransmitSA, Test_CreateTXSA_DriverFails)
{
    void* key_pointer = InstallGoodKey(true, true);

    EXPECT_CALL(mocks, MKA_PHY_AddTxSA(_,_,_,_,_,_,_,_,_))
        .WillOnce(Return(MKA_NOT_OK));

    t_MKA_transmit_sa* sa_pointer = MKA_SECY_CreateTransmitSA(MKA_BUS, 2, 1, 0U, MKA_CONFIDENTIALITY_OFFSET_30, key_pointer);

    EXPECT_EQ(NULL, sa_pointer);
}

TEST_F(Test_MKA_SECY_CreateDestroyTransmitSA, Test_CreateTwoTXSAs_FailCreatingThirdTXSA_DeleteTXSA_CreateTXSAAfterDelete)
{
    void* key_pointer = InstallGoodKey(true, true);
    t_MKA_transmit_sa* sa_pointer1 = CreateTransmitSA(mka_tick_time_ms, key_pointer);
    t_MKA_transmit_sa* sa_pointer2 = CreateTransmitSA(mka_tick_time_ms, key_pointer);
    EXPECT_CALL(mocks, MKA_PHY_AddTxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_transmit_sa* sa_pointer3 = MKA_SECY_CreateTransmitSA(MKA_BUS, 2, 1, 0U, MKA_CONFIDENTIALITY_OFFSET_30, key_pointer);

    EXPECT_NE((t_MKA_transmit_sa*)NULL, sa_pointer1);
    EXPECT_NE((t_MKA_transmit_sa*)NULL, sa_pointer2);
    EXPECT_EQ(NULL, sa_pointer3);

    /*****************************************************************************/

    EXPECT_CALL(mocks, MKA_PHY_DeleteTxSA(MKA_BUS,sa_pointer2->an))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_DestroyTransmitSA(MKA_BUS, sa_pointer2);

    EXPECT_EQ(sa_pointer2->an, 0xFF);

    /*****************************************************************************/

    sa_pointer3 = CreateTransmitSA(mka_tick_time_ms, key_pointer);
    EXPECT_NE((t_MKA_transmit_sa*)NULL, sa_pointer3);
}

TEST_F(Test_MKA_SECY_CreateDestroyTransmitSA, Test_DestroyNULLSA)
{
    EXPECT_CALL(mocks, MKA_PHY_DeleteTxSA(_,_))
        .Times(0);
    MKA_SECY_DestroyTransmitSA(MKA_BUS, NULL);
}

struct Test_MKA_SECY_CreateDestroyReceiveSA : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_CreateDestroyReceiveSA, Test_CreateRXSA_SakNullPointer)
{
    void* key_pointer;
    
    key_pointer = InstallBadKeyWrongSAK();
    EXPECT_CALL(mocks, MKA_PHY_AddRxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_receive_sa* sa_pointer1 = MKA_SECY_CreateReceiveSA(MKA_BUS, 2, 1, 0U, key_pointer);
    EXPECT_EQ(NULL, sa_pointer1);

    key_pointer = InstallBadKeyWrongKI();
    EXPECT_CALL(mocks, MKA_PHY_AddRxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_receive_sa* sa_pointer2 = MKA_SECY_CreateReceiveSA(MKA_BUS, 2, 1, 0U, key_pointer);
    EXPECT_EQ(NULL, sa_pointer2);

    key_pointer = InstallBadKeyErrorCrypto1();
    EXPECT_CALL(mocks, MKA_PHY_AddRxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_receive_sa* sa_pointer3 = MKA_SECY_CreateReceiveSA(MKA_BUS, 2, 1, 0U, key_pointer);
    EXPECT_EQ(NULL, sa_pointer3);

    key_pointer = InstallBadKeyErrorCrypto2();
    EXPECT_CALL(mocks, MKA_PHY_AddRxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_receive_sa* sa_pointer4 = MKA_SECY_CreateReceiveSA(MKA_BUS, 2, 1, 0U, key_pointer);
    EXPECT_EQ(NULL, sa_pointer4);
}

TEST_F(Test_MKA_SECY_CreateDestroyReceiveSA, Test_CreateRXSA_KeyNotValidForRX)
{
    void* key_pointer = InstallGoodKey(true, false);

    EXPECT_CALL(mocks, MKA_PHY_AddRxSA(_,_,_,_,_,_,_,_,_))
    .Times(0);

    t_MKA_receive_sa* sa_pointer = MKA_SECY_CreateReceiveSA(MKA_BUS, 2, 1, 0U, key_pointer);

    EXPECT_EQ(NULL, sa_pointer);
}

TEST_F(Test_MKA_SECY_CreateDestroyReceiveSA, Test_CreateRXSA_DriverFails)
{
    void* key_pointer = InstallGoodKey(true, true);

    EXPECT_CALL(mocks, MKA_PHY_AddRxSA(_,_,_,_,_,_,_,_,_))
        .WillOnce(Return(MKA_NOT_OK));

    t_MKA_receive_sa* sa_pointer = MKA_SECY_CreateReceiveSA(MKA_BUS, 2, 1, 0U, key_pointer);

    EXPECT_EQ(NULL, sa_pointer);
}

TEST_F(Test_MKA_SECY_CreateDestroyReceiveSA, Test_CreateTwoRXSAs_FailCreatingThirdRXSA)
{
    void* key_pointer = InstallGoodKey(true, true);
    t_MKA_receive_sa* sa_pointer1 = CreateReceiveSA(mka_tick_time_ms, key_pointer);
    t_MKA_receive_sa* sa_pointer2 = CreateReceiveSA(mka_tick_time_ms ,key_pointer);
    EXPECT_CALL(mocks, MKA_PHY_AddRxSA(_,_,_,_,_,_,_,_,_))
        .Times(0);
    t_MKA_receive_sa* sa_pointer3 = MKA_SECY_CreateReceiveSA(MKA_BUS, 2, 1, 0U, key_pointer);

    EXPECT_NE((t_MKA_receive_sa*)NULL, sa_pointer1);
    EXPECT_NE((t_MKA_receive_sa*)NULL, sa_pointer2);
    EXPECT_EQ(NULL, sa_pointer3);

    /*****************************************************************************/

    EXPECT_CALL(mocks, MKA_PHY_DeleteRxSA(MKA_BUS,sa_pointer2->an))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_DestroyReceiveSA(MKA_BUS, sa_pointer2);

    EXPECT_EQ(sa_pointer2->an, 0xFF);

    /*****************************************************************************/

    sa_pointer3 = CreateReceiveSA(mka_tick_time_ms, key_pointer);
    EXPECT_NE((t_MKA_receive_sa*)NULL, sa_pointer3);
}

TEST_F(Test_MKA_SECY_CreateDestroyReceiveSA, Test_DestroyNULLSA)
{
    EXPECT_CALL(mocks, MKA_PHY_DeleteRxSA(_,_))
        .Times(0);
    MKA_SECY_DestroyReceiveSA(MKA_BUS, NULL);
}

struct Test_MKA_SECY_EnableTransmitSA : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_EnableTransmitSA, Test_EnableNULLSA)
{
    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(_,_,_,_))
        .Times(0);
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,NULL);
}

TEST_F(Test_MKA_SECY_EnableTransmitSA, Test_DriverFails)
{
    t_MKA_transmit_sc* sc_pointer = CreateTransmitSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_transmit_sa* sa_pointer = CreateTransmitSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(_,_,_,_))
        .WillOnce(Return(MKA_NOT_OK));
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,sa_pointer);
}

TEST_F(Test_MKA_SECY_EnableTransmitSA, Test_EnableSA_EnableSameSAAgainDoNothing_EnableAnotherSA_DestroyBothSAs)
{    
    t_MKA_transmit_sc* sc_pointer = CreateTransmitSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_transmit_sa* sa_pointer1 = CreateTransmitSA(mka_tick_time_ms, key_pointer);
    t_MKA_transmit_sa* sa_pointer2 = CreateTransmitSA(mka_tick_time_ms, key_pointer);

    mka_tick_time_ms += TIME_INCR;

    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(MKA_BUS,sa_pointer1->an,sa_pointer1->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,sa_pointer1);

    EXPECT_TRUE(sa_pointer1->enable_transmit);
    EXPECT_TRUE(sa_pointer1->in_use);
    EXPECT_EQ(sa_pointer1->created_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sa_pointer1->started_time, mka_tick_time_ms);
    EXPECT_EQ(sa_pointer1->stopped_time, mka_tick_time_ms-TIME_INCR);

    EXPECT_TRUE(sc_pointer->transmitting);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms-TIME_INCR);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;

    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(_,_,_,_))
        .Times(0);
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,sa_pointer1);

    EXPECT_TRUE(sa_pointer1->enable_transmit);
    EXPECT_TRUE(sa_pointer1->in_use);
    EXPECT_EQ(sa_pointer1->created_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sa_pointer1->started_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sa_pointer1->stopped_time, mka_tick_time_ms-2*TIME_INCR);

    EXPECT_TRUE(sc_pointer->transmitting);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms-2*TIME_INCR);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;
    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(MKA_BUS,sa_pointer2->an,sa_pointer2->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,sa_pointer2);

    EXPECT_TRUE(sa_pointer2->enable_transmit);
    EXPECT_TRUE(sa_pointer2->in_use);
    EXPECT_EQ(sa_pointer2->created_time, mka_tick_time_ms-3*TIME_INCR);
    EXPECT_EQ(sa_pointer2->started_time, mka_tick_time_ms);
    EXPECT_EQ(sa_pointer2->stopped_time, mka_tick_time_ms-3*TIME_INCR);

    EXPECT_TRUE(sc_pointer->transmitting);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-3*TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms-3*TIME_INCR);

    EXPECT_FALSE(sa_pointer1->enable_transmit);
    EXPECT_FALSE(sa_pointer1->in_use);
    EXPECT_EQ(sa_pointer1->created_time, mka_tick_time_ms-3*TIME_INCR);
    EXPECT_EQ(sa_pointer1->started_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sa_pointer1->stopped_time, mka_tick_time_ms);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;
    EXPECT_CALL(mocks, MKA_PHY_DeleteTxSA(MKA_BUS,sa_pointer1->an))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_DestroyTransmitSA(MKA_BUS, sa_pointer1);

    EXPECT_EQ(sa_pointer1->an, 0xFF);

    EXPECT_TRUE(sc_pointer->transmitting);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;
    EXPECT_CALL(mocks, MKA_PHY_DeleteTxSA(MKA_BUS,sa_pointer2->an))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_DestroyTransmitSA(MKA_BUS, sa_pointer2);

    EXPECT_EQ(sa_pointer2->an, 0xFF);

    EXPECT_FALSE(sc_pointer->transmitting);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-5*TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms-4*TIME_INCR);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms);
}

struct Test_MKA_SECY_EnableReceiveSA : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_EnableReceiveSA, Test_EnableNULLSA)
{
    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(_,_,_,_))
        .Times(0);
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,NULL);
}

TEST_F(Test_MKA_SECY_EnableReceiveSA, Test_DriverFails)
{
    t_MKA_receive_sc* sc_pointer = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_receive_sa* sa_pointer = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(_,_,_,_))
        .WillOnce(Return(MKA_NOT_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer);
}

TEST_F(Test_MKA_SECY_EnableReceiveSA, Test_EnableSA_EnableSameSAAgainDoNothing_EnableAnotherSA_DestroyBothSAs)
{    
    t_MKA_receive_sc* sc_pointer = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_receive_sa* sa_pointer1 = CreateReceiveSA(mka_tick_time_ms, key_pointer);
    t_MKA_receive_sa* sa_pointer2 = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    mka_tick_time_ms += TIME_INCR;

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer1->an,sa_pointer1->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer1);

    EXPECT_TRUE(sa_pointer1->enable_receive);
    EXPECT_TRUE(sa_pointer1->in_use);
    EXPECT_EQ(sa_pointer1->created_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sa_pointer1->started_time, mka_tick_time_ms);
    EXPECT_EQ(sa_pointer1->stopped_time, mka_tick_time_ms-TIME_INCR);

    EXPECT_TRUE(sc_pointer->receiving);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms-TIME_INCR);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(_,_,_,_))
        .Times(0);
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer1);

    EXPECT_TRUE(sa_pointer1->enable_receive);
    EXPECT_TRUE(sa_pointer1->in_use);
    EXPECT_EQ(sa_pointer1->created_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sa_pointer1->started_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sa_pointer1->stopped_time, mka_tick_time_ms-2*TIME_INCR);

    EXPECT_TRUE(sc_pointer->receiving);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms-TIME_INCR);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms-2*TIME_INCR);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;
    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer2->an,sa_pointer2->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer2);

    EXPECT_TRUE(sa_pointer2->enable_receive);
    EXPECT_TRUE(sa_pointer2->in_use);
    EXPECT_EQ(sa_pointer2->created_time, mka_tick_time_ms-3*TIME_INCR);
    EXPECT_EQ(sa_pointer2->started_time, mka_tick_time_ms);
    EXPECT_EQ(sa_pointer2->stopped_time, mka_tick_time_ms-3*TIME_INCR);

    EXPECT_TRUE(sc_pointer->receiving);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-3*TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms-3*TIME_INCR);

    EXPECT_TRUE(sa_pointer1->enable_receive);
    EXPECT_TRUE(sa_pointer1->in_use);
    EXPECT_EQ(sa_pointer1->created_time, mka_tick_time_ms-3*TIME_INCR);
    EXPECT_EQ(sa_pointer1->started_time, mka_tick_time_ms-2*TIME_INCR);
    EXPECT_EQ(sa_pointer1->stopped_time, mka_tick_time_ms-3*TIME_INCR);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;
    EXPECT_CALL(mocks, MKA_PHY_DeleteRxSA(MKA_BUS,sa_pointer1->an))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_DestroyReceiveSA(MKA_BUS, sa_pointer1);

    EXPECT_EQ(sa_pointer1->an, 0xFF);

    EXPECT_TRUE(sc_pointer->receiving);

    /*****************************************************************************/

    mka_tick_time_ms += TIME_INCR;
    EXPECT_CALL(mocks, MKA_PHY_DeleteRxSA(MKA_BUS,sa_pointer2->an))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_DestroyReceiveSA(MKA_BUS, sa_pointer2);

    EXPECT_EQ(sa_pointer2->an, 0xFF);

    EXPECT_FALSE(sc_pointer->receiving);
    EXPECT_EQ(sc_pointer->created_time, mka_tick_time_ms-5*TIME_INCR);
    EXPECT_EQ(sc_pointer->started_time, mka_tick_time_ms-4*TIME_INCR);
    EXPECT_EQ(sc_pointer->stopped_time, mka_tick_time_ms);
}

struct Test_MKA_SECY_CleanSAKFromRAM : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_CleanSAKFromRAM, Test_CleanSAKAfterEnableTx)
{
    t_MKA_transmit_sc* sc_pointer_tx = CreateTransmitSC(mka_tick_time_ms);
    t_MKA_receive_sc* sc_pointer_rx = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_transmit_sa* sa_pointer_tx = CreateTransmitSA(mka_tick_time_ms, key_pointer);
    t_MKA_receive_sa*  sa_pointer_rx = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(MKA_BUS,sa_pointer_tx->an,sa_pointer_tx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,sa_pointer_tx);

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,sa_pointer_rx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer_rx);

    memset(&test_sak, 0, sizeof(t_MKA_key));
    memset(&test_hash, 0, sizeof(t_MKA_key));
    memset(&test_salt, 0, sizeof(t_MKA_key));
    EXPECT_TRUE( 0==memcmp( &test_sak, &(reinterpret_cast<t_MKA_data_key*>(key_pointer)->SAK), sizeof(t_MKA_key)) );
    EXPECT_TRUE( 0==memcmp( &test_sak, &(reinterpret_cast<t_MKA_data_key*>(key_pointer)->HASH), sizeof(t_MKA_key)) );
    EXPECT_TRUE( 0==memcmp( &test_sak, &(reinterpret_cast<t_MKA_data_key*>(key_pointer)->SALT), sizeof(t_MKA_key)) );
}

TEST_F(Test_MKA_SECY_CleanSAKFromRAM, Test_CleanSAKAfterEnableRx)
{
    t_MKA_transmit_sc* sc_pointer_tx = CreateTransmitSC(mka_tick_time_ms);
    t_MKA_receive_sc* sc_pointer_rx = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_transmit_sa* sa_pointer_tx = CreateTransmitSA(mka_tick_time_ms, key_pointer);
    t_MKA_receive_sa*  sa_pointer_rx = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,sa_pointer_rx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer_rx);

    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(MKA_BUS,sa_pointer_tx->an,sa_pointer_tx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,sa_pointer_tx);

    memset(&test_sak, 0, sizeof(t_MKA_key));
    memset(&test_hash, 0, sizeof(t_MKA_key));
    memset(&test_salt, 0, sizeof(t_MKA_key));
    EXPECT_TRUE( 0==memcmp( &test_sak, &(reinterpret_cast<t_MKA_data_key*>(key_pointer)->SAK), sizeof(t_MKA_key)) );
    EXPECT_TRUE( 0==memcmp( &test_sak, &(reinterpret_cast<t_MKA_data_key*>(key_pointer)->HASH), sizeof(t_MKA_key)) );
    EXPECT_TRUE( 0==memcmp( &test_sak, &(reinterpret_cast<t_MKA_data_key*>(key_pointer)->SALT), sizeof(t_MKA_key)) );
}

struct Test_MKA_SECY_UpdateNextPN : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_UpdateNextPN, Test_UpdateNextPNWithNullSA)
{
    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(_,_,_,_))
        .Times(0);
    MKA_SECY_ReceiveSA_UpdateNextPN(MKA_BUS, NULL, 2000);
}

TEST_F(Test_MKA_SECY_UpdateNextPN, Test_DriverFails)
{
    test_secy_config_1.protect_frames = true;
    test_secy_config_1.replay_protect = true;
    test_secy_config_1.replay_window = 4;
    test_secy_config_1.validate_frames = MKA_VALIDATE_STRICT;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_256;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_30;
    test_secy_config_1.controlled_port_enabled = true;

    memset(&test_sci_1, 0xFF, sizeof(t_MKA_sci));

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);

    /*****************************************************************************/

    t_MKA_receive_sc* sc_pointer = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_receive_sa*  sa_pointer_rx = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,sa_pointer_rx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer_rx);

    /*****************************************************************************/
        
    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,test_secy_config_1.replay_window +5,true))
        .WillOnce(Return(MKA_NOT_OK));

    MKA_SECY_ReceiveSA_UpdateNextPN(MKA_BUS, sa_pointer_rx, test_secy_config_1.replay_window +5);

    EXPECT_EQ(0x87541269, sa_pointer_rx->next_pn);
    EXPECT_EQ(0x87541269, sa_pointer_rx->lowest_pn);
}

TEST_F(Test_MKA_SECY_UpdateNextPN, Test_UpdateNextPNGreaterThatWindowWithNullSA)
{
    test_secy_config_1.protect_frames = true;
    test_secy_config_1.replay_protect = true;
    test_secy_config_1.replay_window = 4;
    test_secy_config_1.validate_frames = MKA_VALIDATE_STRICT;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_256;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_30;
    test_secy_config_1.controlled_port_enabled = true;

    memset(&test_sci_1, 0xFF, sizeof(t_MKA_sci));

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);

    /*****************************************************************************/

    t_MKA_receive_sc* sc_pointer = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_receive_sa*  sa_pointer_rx = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,sa_pointer_rx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer_rx);

    /*****************************************************************************/
        
    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,test_secy_config_1.replay_window +5,true))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_ReceiveSA_UpdateNextPN(MKA_BUS, sa_pointer_rx, test_secy_config_1.replay_window +5);

    EXPECT_EQ(test_secy_config_1.replay_window +5, sa_pointer_rx->next_pn);
    EXPECT_EQ(5, sa_pointer_rx->lowest_pn);
}

TEST_F(Test_MKA_SECY_UpdateNextPN, Test_UpdateNextPNLowerThatWindowWithNullSA)
{
    test_secy_config_1.protect_frames = true;
    test_secy_config_1.replay_protect = true;
    test_secy_config_1.replay_window = 4;
    test_secy_config_1.validate_frames = MKA_VALIDATE_STRICT;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_256;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_30;
    test_secy_config_1.controlled_port_enabled = true;

    memset(&test_sci_1, 0xFF, sizeof(t_MKA_sci));

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);

    /*****************************************************************************/

    t_MKA_receive_sc* sc_pointer = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_receive_sa*  sa_pointer_rx = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,sa_pointer_rx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer_rx);

    /*****************************************************************************/
        
    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,test_secy_config_1.replay_window-1,true))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_ReceiveSA_UpdateNextPN(MKA_BUS, sa_pointer_rx, test_secy_config_1.replay_window-1);

    EXPECT_EQ(test_secy_config_1.replay_window-1, sa_pointer_rx->next_pn);
    EXPECT_EQ(1, sa_pointer_rx->lowest_pn);
}

TEST_F(Test_MKA_SECY_UpdateNextPN, Test_UpdateNextPNEqualThatWindowWithNullSA)
{
    test_secy_config_1.protect_frames = true;
    test_secy_config_1.replay_protect = true;
    test_secy_config_1.replay_window = 4;
    test_secy_config_1.validate_frames = MKA_VALIDATE_STRICT;
    test_secy_config_1.current_cipher_suite = MKA_CS_ID_GCM_AES_256;
    test_secy_config_1.confidentiality_offset = MKA_CONFIDENTIALITY_OFFSET_30;
    test_secy_config_1.controlled_port_enabled = true;

    memset(&test_sci_1, 0xFF, sizeof(t_MKA_sci));

    EXPECT_CALL(mocks, MKA_PHY_UpdateSecY(MKA_BUS,CompareSecYConfig(&test_secy_config_1),CompareSci(&test_sci_1)))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_UpdateConfiguration(MKA_BUS, &test_secy_config_1);

    /*****************************************************************************/

    t_MKA_receive_sc* sc_pointer = CreateReceiveSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_receive_sa*  sa_pointer_rx = CreateReceiveSA(mka_tick_time_ms, key_pointer);

    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,sa_pointer_rx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_ReceiveSA_EnableReceive(MKA_BUS,sa_pointer_rx);

    /*****************************************************************************/
        
    EXPECT_CALL(mocks, MKA_PHY_UpdateRxSA(MKA_BUS,sa_pointer_rx->an,test_secy_config_1.replay_window,true))
        .WillOnce(Return(MKA_OK));

    MKA_SECY_ReceiveSA_UpdateNextPN(MKA_BUS, sa_pointer_rx, test_secy_config_1.replay_window);

    EXPECT_EQ(test_secy_config_1.replay_window, sa_pointer_rx->next_pn);
    EXPECT_EQ(1, sa_pointer_rx->lowest_pn);
}

struct Test_MKA_SECY_TransmitSA_UpdateNextPN : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_TransmitSA_UpdateNextPN, Test_NullSA)
{
    EXPECT_CALL(mocks, MKA_PHY_GetTxSANextPN(_,_,_))
        .Times(0);
    MKA_SECY_TransmitSA_UpdateNextPN(MKA_BUS, NULL);
}

TEST_F(Test_MKA_SECY_TransmitSA_UpdateNextPN, Test_SAInUse_UpdatedNextPN)
{
    t_MKA_transmit_sc* sc_pointer_tx = CreateTransmitSC(mka_tick_time_ms);
    void* key_pointer = InstallGoodKey(true,true);
    t_MKA_transmit_sa* sa_pointer_tx = CreateTransmitSA(mka_tick_time_ms, key_pointer);
    EXPECT_CALL(mocks, MKA_PHY_UpdateTxSA(MKA_BUS,sa_pointer_tx->an,sa_pointer_tx->next_pn,true))
        .WillOnce(Return(MKA_OK));
    MKA_SECY_TransmitSA_EnableTransmit(MKA_BUS,sa_pointer_tx);

    EXPECT_CALL(mocks, MKA_PHY_GetTxSANextPN(MKA_BUS,sa_pointer_tx->an,_))
        .WillOnce(DoAll(SetArgPointee<2>(0x55554444), Return(MKA_OK)));

    MKA_SECY_TransmitSA_UpdateNextPN(MKA_BUS, sa_pointer_tx);

    EXPECT_EQ(0x55554444, sa_pointer_tx->next_pn);
}

struct Test_MKA_SECY_MainFunction : public Test_MKA_SECY_Base {
};

TEST_F(Test_MKA_SECY_MainFunction, Test_PollingTimerNotExpired)
{
    EXPECT_CALL(mocks, MKA_PHY_GetMacSecStats(_,_,_,_,_))
        .Times(0);

    MKA_SECY_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_SECY_MainFunction, Test_PollingTimerExpired_GetMacSecStatsFail)
{
    t_MKA_stats_transmit_secy get_stats_tx_secy;
    t_MKA_stats_receive_secy  get_stats_rx_secy;
    t_MKA_stats_transmit_sc   get_stats_tx_sc;
    t_MKA_stats_receive_sc    get_stats_rx_sc;

    mka_tick_time_ms += MKA_active_global_config->secy_polling_ms;

    EXPECT_CALL(mocks, MKA_PHY_GetMacSecStats(_,_,_,_,_))
        .WillOnce(Return(MKA_NOT_OK));

    MKA_SECY_MainFunction(MKA_BUS);

    t_MKA_result ret = MKA_SECY_GetMacSecStats(MKA_BUS, &get_stats_tx_secy, &get_stats_rx_secy, &get_stats_tx_sc, &get_stats_rx_sc);
    EXPECT_EQ(ret, MKA_NOT_OK);
}

TEST_F(Test_MKA_SECY_MainFunction, Test_PollingTimerExpired_GetMacSecStatsOK)
{
    t_MKA_stats_transmit_secy get_stats_tx_secy;
    t_MKA_stats_receive_secy  get_stats_rx_secy;
    t_MKA_stats_transmit_sc   get_stats_tx_sc;
    t_MKA_stats_receive_sc    get_stats_rx_sc;

    t_MKA_stats_transmit_secy test_stats_tx_secy = {1,2,3,4};
    t_MKA_stats_receive_secy  test_stats_rx_secy = {1,2,3,4,5,6,7,8};
    t_MKA_stats_transmit_sc   test_stats_tx_sc   = {1,2};
    t_MKA_stats_receive_sc    test_stats_rx_sc   = {1,2,3,4,5,6};

    mka_tick_time_ms += MKA_active_global_config->secy_polling_ms;

    EXPECT_CALL(mocks, MKA_PHY_GetMacSecStats(_,_,_,_,_))
        .WillOnce(DoAll(SetStatsTxSecY(&test_stats_tx_secy),
                        SetStatsRxSecY(&test_stats_rx_secy),
                        SetStatsTxSC(&test_stats_tx_sc),
                        SetStatsRxSC(&test_stats_rx_sc),
                        Return(MKA_OK)));

    MKA_SECY_MainFunction(MKA_BUS);

    t_MKA_result ret = MKA_SECY_GetMacSecStats(MKA_BUS, &get_stats_tx_secy, &get_stats_rx_secy, &get_stats_tx_sc, &get_stats_rx_sc);
    EXPECT_EQ(ret, MKA_OK);
    EXPECT_EQ(0, memcmp(&get_stats_tx_secy, &test_stats_tx_secy, sizeof(t_MKA_stats_transmit_secy)));
    EXPECT_EQ(0, memcmp(&get_stats_rx_secy, &test_stats_rx_secy, sizeof(t_MKA_stats_receive_secy)));
    EXPECT_EQ(0, memcmp(&get_stats_tx_sc, &test_stats_tx_sc, sizeof(t_MKA_stats_transmit_sc)));
    EXPECT_EQ(0, memcmp(&get_stats_rx_sc, &test_stats_rx_sc, sizeof(t_MKA_stats_receive_sc)));
}
