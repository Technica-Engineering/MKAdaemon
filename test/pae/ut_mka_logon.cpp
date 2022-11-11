/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: ut_mka_logon.cpp
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

#include "mka_logon.h"

#define MKA_BUS 0

extern "C" void mock_assertion_action(void){ }
extern "C" void mock_print(char const* text, unsigned long length)
{
    printf("%s", text);
}

t_MKA_bus_config const* MKA_active_buses_config = nullptr;

static t_MKA_key CAK_test = {{0,1,2,3,4}, 5U};
static t_MKA_ckn CKN_test = {"CAK1", 4U};
static t_MKA_key KEK_test = {{1,2,3,4,5,6}, 6U};
static t_MKA_key ICK_test = {{9,8,7}, 3U};
static uint32_t timer_test = MKA_TIMER_MAX;

class Test_MKA_LOGON_Base : public ::testing::Test {
   protected:
   public:
    Mock::Mocks mocks;
    t_MKA_bus_config test_buses_active_config = {
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
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    Test_MKA_LOGON_Base(void)
    {
        MKA_active_buses_config = &test_buses_active_config;
    }

    ~Test_MKA_LOGON_Base(void)
    {
        MKA_active_buses_config = nullptr;
    }

    virtual void SetUp(void)
    {
        MKA_LOGON_Init(MKA_BUS);
        MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    }

    virtual void TearDown(void)
    {
    }

    void SetNewConfig(t_MKA_bus_config* config)
    {
        MKA_active_buses_config = config;
    }

    void GetKeysAndCreateMKA(void)
    {
        MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
        MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
        MKA_LOGON_SetKayEnabled(MKA_BUS, true);

        EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
            .WillOnce(DoAll(SetArgPointee<1>(CAK_test), SetArgPointee<2>(CKN_test),  Return(MKA_OK)));
        EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
            .WillOnce(DoAll(SetArgPointee<1>(KEK_test),  Return(MKA_OK)));
        EXPECT_CALL(mocks, MKA_RetrieveICK(MKA_BUS,_))
            .WillOnce(DoAll(SetArgPointee<1>(ICK_test),  Return(MKA_OK)));
        EXPECT_CALL(mocks, MKA_KAY_CreateMKA(MKA_BUS,ObjectMatch(CKN_test),ObjectMatch(CAK_test),ObjectMatch(KEK_test),ObjectMatch(ICK_test),NULL,Eq(timer_test)))
            .WillOnce(Return(true));
        EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,true))
            .Times(1);

        EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
            .Times(0);
        EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
            .Times(0);

        MKA_LOGON_MainFunction(MKA_BUS);
    }

    void LinkDownAndDeleteMKA(void)
    {
        GetKeysAndCreateMKA();

        /* Expectations MKA_LOGON_MainFunction */
        EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(_,_,_))
            .Times(0);
        EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
            .Times(0);
        EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
            .Times(0);
        EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
            .Times(0);
        EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
            .Times(0);

        EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
            .Times(0);
        EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
            .Times(0);

        EXPECT_CALL(mocks, MKA_KAY_DeleteMKA(MKA_BUS))
            .Times(1);

        MKA_LOGON_SetPortEnabled(MKA_BUS,false);
        MKA_LOGON_SetPortEnabled(MKA_BUS,false);
        MKA_LOGON_SetPortEnabled(MKA_BUS,false);
        MKA_LOGON_MainFunction(MKA_BUS);
        MKA_LOGON_SignalDeletedMKA(MKA_BUS);
        MKA_LOGON_SetPortEnabled(MKA_BUS,false);
        MKA_LOGON_SetPortEnabled(MKA_BUS,false);
        MKA_LOGON_MainFunction(MKA_BUS);
    }
};

struct Test_MKA_LOGON_MainFunction : public Test_MKA_LOGON_Base,
        public ::testing::WithParamInterface<std::tuple<bool, bool>> {
};

TEST_P(Test_MKA_LOGON_MainFunction, DoNothing_WhenLogonOrPortDisabled)
{
    MKA_LOGON_SetLogonEnabled(MKA_BUS, std::get<0>(GetParam()));
    MKA_LOGON_SetPortEnabled(MKA_BUS, std::get<1>(GetParam()));

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);
}

INSTANTIATE_TEST_SUITE_P(MKAOrPortDisabled, Test_MKA_LOGON_MainFunction, ::testing::Values(
    std::make_tuple(false, false), std::make_tuple(false, true), std::make_tuple(true, false)
));

TEST_F(Test_MKA_LOGON_MainFunction, SetCPUnauthenticated_WhenKaYDisabledAndUnauthAllowedDifferentFromNever)
{
    /******** CONFIG1 ********/
    t_MKA_bus_config config1 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config1);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, false);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(1);

    MKA_LOGON_MainFunction(MKA_BUS);

    /******** CONFIG2 ********/
    t_MKA_bus_config config2 = {
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
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config2);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, false);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(1);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, SetCPUnauthenticated_WhenRetrieveCAKCKNFailsAndUnauthAllowedDifferentFromNever)
{
    /******** CONFIG1 ********/
    t_MKA_bus_config config1 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config1);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);

    /******** CONFIG2 ********/
    t_MKA_bus_config config2 = {
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
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config2);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(1);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, SetCPUnauthenticated_WhenRetrieveKEKFailsAndUnauthAllowedDifferentFromNever)
{
    /******** CONFIG1 ********/
    t_MKA_bus_config config1 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config1);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(Return(MKA_OK));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);

    /******** CONFIG2 ********/
    t_MKA_bus_config config2 = {
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
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config2);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(Return(MKA_OK));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(1);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, SetCPUnauthenticated_WhenRetrieveICKFailsAndUnauthAllowedDifferentFromNever)
{
    /******** CONFIG1 ********/
    t_MKA_bus_config config1 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config1);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(Return(MKA_OK));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(Return(MKA_OK));
    EXPECT_CALL(mocks, MKA_RetrieveICK(MKA_BUS,_))
        .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);

    /******** CONFIG2 ********/
    t_MKA_bus_config config2 = {
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
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config2);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(Return(MKA_OK));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(Return(MKA_OK));
    EXPECT_CALL(mocks, MKA_RetrieveICK(MKA_BUS,_))
        .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(1);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, SetCPUnauthenticated_WhenCreateMKAFailsAndUnauthAllowedDifferentFromNever)
{
    /******** CONFIG1 ********/
    t_MKA_bus_config config1 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config1);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(DoAll(SetArgPointee<1>(CAK_test), SetArgPointee<2>(CKN_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(KEK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveICK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(ICK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(MKA_BUS,ObjectMatch(CKN_test),ObjectMatch(CAK_test),ObjectMatch(KEK_test),ObjectMatch(ICK_test),NULL,Eq(timer_test)))
        .WillOnce(Return(false));
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);

    /******** CONFIG2 ********/
    t_MKA_bus_config config2 = {
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
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config2);

    MKA_LOGON_SetLogonEnabled(MKA_BUS, true);
    MKA_LOGON_SetPortEnabled(MKA_BUS,  true);
    MKA_LOGON_SetKayEnabled(MKA_BUS, true);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(DoAll(SetArgPointee<1>(CAK_test), SetArgPointee<2>(CKN_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(KEK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveICK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(ICK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(MKA_BUS,ObjectMatch(CKN_test),ObjectMatch(CAK_test),ObjectMatch(KEK_test),ObjectMatch(ICK_test),NULL,Eq(timer_test)))
        .WillOnce(Return(false));
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(1);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, RetrieveKeys_And_CreateMKASuccess)
{
    GetKeysAndCreateMKA();
}

TEST_F(Test_MKA_LOGON_MainFunction, IfMKADeleted_CreateMKA)
{
    GetKeysAndCreateMKA();
    MKA_LOGON_SignalDeletedMKA(MKA_BUS);

    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(DoAll(SetArgPointee<1>(CAK_test), SetArgPointee<2>(CKN_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(KEK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveICK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(ICK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(MKA_BUS,ObjectMatch(CKN_test),ObjectMatch(CAK_test),ObjectMatch(KEK_test),ObjectMatch(ICK_test),NULL,Eq(timer_test)))
        .WillOnce(Return(true));
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,true))
        .Times(1);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, IfLinkDown_DeleteMKA)
{
    LinkDownAndDeleteMKA();
}

TEST_F(Test_MKA_LOGON_MainFunction, IfLinkDownWhenMKADisabled_DoNothing)
{
    GetKeysAndCreateMKA();
    MKA_LOGON_SetKayEnabled(MKA_BUS, false);

    /* Expectations MKA_LOGON_MainFunction */
    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_KAY_DeleteMKA(_))
        .Times(0);

    MKA_LOGON_SetPortEnabled(MKA_BUS,false);
    MKA_LOGON_SetPortEnabled(MKA_BUS,false);
    MKA_LOGON_SetPortEnabled(MKA_BUS,false);
    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, IfLinkDownWhenMKANotCreated_DoNothing)
{
    GetKeysAndCreateMKA();
    MKA_LOGON_SignalDeletedMKA(MKA_BUS);

    /* Expectations MKA_LOGON_MainFunction */
    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveKEK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_RetrieveICK(_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(_,_,_,_,_,_,_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_KAY_DeleteMKA(_))
        .Times(0);

    MKA_LOGON_SetPortEnabled(MKA_BUS,false);
    MKA_LOGON_SetPortEnabled(MKA_BUS,false);
    MKA_LOGON_SetPortEnabled(MKA_BUS,false);
    MKA_LOGON_MainFunction(MKA_BUS);
}

TEST_F(Test_MKA_LOGON_MainFunction, IfLinkUp_CreateMKAAgain)
{
    LinkDownAndDeleteMKA();

    /* Expectations MKA_LOGON_MainFunction */
    EXPECT_CALL(mocks, MKA_RetrieveCAKCKN(MKA_BUS,_,_))
        .WillOnce(DoAll(SetArgPointee<1>(CAK_test), SetArgPointee<2>(CKN_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveKEK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(KEK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_RetrieveICK(MKA_BUS,_))
        .WillOnce(DoAll(SetArgPointee<1>(ICK_test),  Return(MKA_OK)));
    EXPECT_CALL(mocks, MKA_KAY_CreateMKA(MKA_BUS,ObjectMatch(CKN_test),ObjectMatch(CAK_test),ObjectMatch(KEK_test),ObjectMatch(ICK_test),NULL,Eq(timer_test)))
        .WillOnce(Return(true));
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,true))
        .Times(1);

    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(_))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectPending(_))
        .Times(0);

    EXPECT_CALL(mocks, MKA_KAY_DeleteMKA(_))
        .Times(0);

    MKA_LOGON_SetPortEnabled(MKA_BUS,true);
    MKA_LOGON_MainFunction(MKA_BUS);
}

struct Test_MKA_LOGON_SetKayConnectMode : public Test_MKA_LOGON_Base,
        public ::testing::WithParamInterface<t_MKA_connect_mode> {
};

TEST_P(Test_MKA_LOGON_SetKayConnectMode, ReceiveConnectFromKaY_ReportToCP)
{
    GetKeysAndCreateMKA();

    /******** CONFIG1 ********/
    t_MKA_bus_config config1 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config1);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(((GetParam()==MKA_PENDING) || (GetParam()==MKA_FAILED)) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);
    
    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());

    /******** CONFIG2 ********/
    t_MKA_bus_config config2 = {
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
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config2);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(((GetParam()==MKA_PENDING) || (GetParam()==MKA_FAILED) || (GetParam()==MKA_AUTHENTICATED)) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);
    
    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());

    /******** CONFIG3 ********/
    t_MKA_bus_config config3 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_ON_MKA_FAIL
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config3);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times((GetParam()==MKA_PENDING) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(((GetParam()==MKA_FAILED) || (GetParam()==MKA_AUTHENTICATED)) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);
    
    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());

    /******** CONFIG4 ********/
    t_MKA_bus_config config4 = {
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
            .unauth_allowed = MKA_UNAUTH_NEVER,
            .unsecure_allowed = MKA_UNSECURE_PER_MKA_SERVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config4);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(((GetParam()==MKA_PENDING) || (GetParam()==MKA_FAILED))? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times((GetParam()==MKA_AUTHENTICATED) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);

    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());

    /******** CONFIG5 ********/
    t_MKA_bus_config config5 = {
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
            .unsecure_allowed = MKA_UNSECURE_NEVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config5);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(((GetParam()==MKA_PENDING) || (GetParam()==MKA_FAILED)) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);

    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());

    /******** CONFIG6 ********/
    t_MKA_bus_config config6 = {
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
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config6);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(((GetParam()==MKA_PENDING) || (GetParam()==MKA_FAILED) || (GetParam()==MKA_AUTHENTICATED)) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);

    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());

    /******** CONFIG7 ********/
    t_MKA_bus_config config7 = {
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
            .unsecure_allowed = MKA_UNSECURE_ON_MKA_FAIL
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config7);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times((GetParam()==MKA_PENDING) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(((GetParam()==MKA_FAILED) || (GetParam()==MKA_AUTHENTICATED)) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);

    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());

    /******** CONFIG8 ********/
    t_MKA_bus_config config8 = {
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
            .unsecure_allowed = MKA_UNSECURE_PER_MKA_SERVER
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = {
                &MKA_RetrieveCAKCKN,
                &MKA_RetrieveKEK,
                &MKA_RetrieveICK
            },
            .cipher_preference = {0ULL},
            .conf_offset_preference = MKA_CONFIDENTIALITY_NONE,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    SetNewConfig(&config8);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(((GetParam()==MKA_PENDING) || (GetParam()==MKA_FAILED)) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times((GetParam()==MKA_AUTHENTICATED) ? 1:0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times((GetParam()==MKA_SECURED) ? 1:0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times((GetParam()==MKA_FAILED) ? 1:0);

    MKA_LOGON_SetKayConnectMode(MKA_BUS,GetParam());
}

INSTANTIATE_TEST_SUITE_P(MKAOrPortDisabled, Test_MKA_LOGON_SetKayConnectMode, ::testing::Values(
    MKA_PENDING,
    MKA_UNAUTHENTICATED,
    MKA_AUTHENTICATED,
    MKA_SECURED,
    MKA_FAILED,
    (t_MKA_connect_mode)0xFF
));

TEST_F(Test_MKA_LOGON_SetKayConnectMode, IfLogonDisabled_DoNothing)
{
    GetKeysAndCreateMKA();
    MKA_LOGON_SetLogonEnabled(MKA_BUS, false);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times(0);
    
    MKA_LOGON_SetKayConnectMode(MKA_BUS,MKA_SECURED);
}

TEST_F(Test_MKA_LOGON_SetKayConnectMode, IfKaYDisabled_DoNothing)
{
    GetKeysAndCreateMKA();
    MKA_LOGON_SetKayEnabled(MKA_BUS, false);

    EXPECT_CALL(mocks, MKA_CP_ConnectPending(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectUnauthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectAuthenticated(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_CP_ConnectSecure(MKA_BUS))
        .Times(0);
    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times(0);
    
    MKA_LOGON_SetKayConnectMode(MKA_BUS,MKA_SECURED);
}

struct Test_MKA_LOGON_SetActivate : public Test_MKA_LOGON_Base {
};

TEST_F(Test_MKA_LOGON_SetActivate, CurrentActivateOnOperUp_SetActivateAlways)
{
    MKA_LOGON_SetActivate(MKA_BUS, MKA_ACTIVATE_ONOPERUP);
    GetKeysAndCreateMKA();

    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,true))
        .Times(1);
    
    MKA_LOGON_SetActivate(MKA_BUS, MKA_ACTIVATE_ALWAYS);
}

TEST_F(Test_MKA_LOGON_SetActivate, CurrentActivateAlways_SetActivateOnOperUp)
{
    MKA_LOGON_SetActivate(MKA_BUS, MKA_ACTIVATE_ALWAYS);
    GetKeysAndCreateMKA();

    EXPECT_CALL(mocks, MKA_KAY_Participate(MKA_BUS,false))
        .Times(1);
    
    MKA_LOGON_SetActivate(MKA_BUS, MKA_ACTIVATE_ONOPERUP);
}

TEST_F(Test_MKA_LOGON_SetActivate, CurrentActivateOnOperUp_SetActivateDisabled)
{
    MKA_LOGON_SetActivate(MKA_BUS, MKA_ACTIVATE_ALWAYS);
    GetKeysAndCreateMKA();

    EXPECT_CALL(mocks, MKA_KAY_Participate(_,_))
        .Times(0);
    
    MKA_LOGON_SetActivate(MKA_BUS, MKA_ACTIVATE_DISABLED);
}
