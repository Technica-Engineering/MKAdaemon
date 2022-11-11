/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-yaml-importer.cpp
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
#include <assert.h>
#include <yaml.h>

#include "mocks.h"
#include "ut_helpers.h"
#include "mka_private.h"


extern "C" t_MKA_config mka_config;

struct BasicElement {
    char const* value;
    BasicElement(void) : value(NULL) {}
    BasicElement(char const*ivalue) : value(ivalue) {}

    operator char const*(void) const { return value; }
    operator BasicElement const*(void) const { return this; }
    BasicElement& operator=(char const*other) { value = other; return *this; }

    char const* serialise(char const* prefix) const {
        if (!value) return "";
        static char buffer[256];
        (void)snprintf(buffer, sizeof(buffer), "%s%s", prefix, value);
        return buffer;
    }
};

struct Interface {
    bool enable = false;
    BasicElement macsec           = NULL;
    BasicElement announcements    = NULL;
    BasicElement listener         = NULL;
    BasicElement device           = NULL;
    BasicElement device_macsec    = NULL;
    BasicElement kay              = NULL;
    BasicElement priority         = NULL;
    BasicElement role             = NULL;
    BasicElement replay_protect   = NULL;
    BasicElement delay_protect    = NULL;
    BasicElement unauth_allowed   = NULL;
    BasicElement unsecure_allowed = NULL;
    BasicElement ciphers          = NULL;
    BasicElement cak              = NULL;
    BasicElement ckn              = NULL;
    BasicElement intf_mode        = NULL;
    BasicElement drv_macsec_mode  = NULL;
    BasicElement mc_uart          = NULL;
    BasicElement phy_vlan_bypass  = NULL;
    BasicElement phy_vlan_list    = NULL;
    BasicElement phy_proto_bypass = NULL;
    BasicElement phy_mac_bypass   = NULL;
    BasicElement phy_transmit_sci = NULL;
    BasicElement phy_transmit_mtu = NULL;
    BasicElement raw_line         = nullptr;

    char const* serialise(void) {
        if (!enable) return "";
        static char buffer[2048];
        size_t p = 0U;

        p += sprintf(&buffer[p], "%s\n", device           .serialise((p==0) ? "  - device: " : "    device: "));
        p += sprintf(&buffer[p], "%s\n", device_macsec    .serialise((p==0) ? "  - protected_device: " : "    protected_device: "));
        p += sprintf(&buffer[p], "%s\n", intf_mode        .serialise((p==0) ? "  - intf_mode: " : "    intf_mode: "));
        p += sprintf(&buffer[p], "%s\n", macsec           .serialise((p==0) ? "  - macsec: " : "    macsec: "));
        p += sprintf(&buffer[p], "%s\n", announcements    .serialise((p==0) ? "  - announcements: " : "    announcements: "));
        p += sprintf(&buffer[p], "%s\n", listener         .serialise((p==0) ? "  - listener: " : "    listener: "));
        p += sprintf(&buffer[p], "%s\n", kay              .serialise((p==0) ? "  - kay: " : "    kay: "));
        p += sprintf(&buffer[p], "%s\n", priority         .serialise((p==0) ? "  - priority: " : "    priority: "));
        p += sprintf(&buffer[p], "%s\n", role             .serialise((p==0) ? "  - role: " : "    role: "));
        p += sprintf(&buffer[p], "%s\n", replay_protect   .serialise((p==0) ? "  - replay_protect: " : "    replay_protect: "));
        p += sprintf(&buffer[p], "%s\n", delay_protect    .serialise((p==0) ? "  - delay_protect: " : "    delay_protect: "));
        p += sprintf(&buffer[p], "%s\n", unauth_allowed   .serialise((p==0) ? "  - unauth_allowed: " : "    unauth_allowed: "));
        p += sprintf(&buffer[p], "%s\n", unsecure_allowed .serialise((p==0) ? "  - unsecure_allowed: " : "    unsecure_allowed: "));
        p += sprintf(&buffer[p], "%s\n", ciphers          .serialise((p==0) ? "  - ciphers: " : "    ciphers: "));
        p += sprintf(&buffer[p], "%s\n", cak              .serialise((p==0) ? "  - cak: " : "    cak: "));
        p += sprintf(&buffer[p], "%s\n", ckn              .serialise((p==0) ? "  - ckn: " : "    ckn: "));
        p += sprintf(&buffer[p], "%s\n", drv_macsec_mode  .serialise((p==0) ? "  - drv_macsec_mode: " : "    drv_macsec_mode: "));
        p += sprintf(&buffer[p], "%s\n", mc_uart          .serialise((p==0) ? "  - mc_uart: " : "    mc_uart: "));
        p += sprintf(&buffer[p], "%s\n", phy_vlan_bypass  .serialise((p==0) ? "  - phy_vlan_bypass: " : "    phy_vlan_bypass: "));
        p += sprintf(&buffer[p], "%s\n", phy_vlan_list    .serialise((p==0) ? "  - phy_vlan_list: " : "    phy_vlan_list: "));
        p += sprintf(&buffer[p], "%s\n", phy_proto_bypass .serialise((p==0) ? "  - phy_proto_bypass: " : "    phy_proto_bypass: "));
        p += sprintf(&buffer[p], "%s\n", phy_mac_bypass   .serialise((p==0) ? "  - phy_mac_bypass: " : "    phy_mac_bypass: "));
        p += sprintf(&buffer[p], "%s\n", phy_transmit_sci .serialise((p==0) ? "  - phy_transmit_sci: " : "    phy_transmit_sci: "));
        p += sprintf(&buffer[p], "%s\n", phy_transmit_mtu .serialise((p==0) ? "  - phy_transmit_mtu: " : "    phy_transmit_mtu: "));
        p += sprintf(&buffer[p], "%s\n", raw_line         .serialise(""));

        return buffer;
    }
};

struct Configuration {
    BasicElement log_level               = "debug";
    BasicElement verbosity               = "1";
    BasicElement hello_time              = "2000";
    BasicElement bounded_hello_time      = "500";
    BasicElement life_time               = "6000";
    BasicElement sak_retire_time         = "3000";
    BasicElement hello_time_rampup       = "100 200 400 800 800";
    BasicElement transmit_empty_dist_sak = "on";
    BasicElement transmit_empty_sak_use  = "on";
    BasicElement transmit_null_xpn       = "on";
    BasicElement secy_polling_ms         = "500";
    BasicElement raw_line                = nullptr;

    Interface   interfaces[2] = {
        {
            .enable = true,
            .macsec = "INTEGRITY",
            .announcements = "off",
            .listener = "off",
            .device = "eth0",
            .device_macsec = "macsec0",
            .kay = "on",
            .priority = "128",
            .role = "AUTO",
            .replay_protect = "0",
            .delay_protect = "on",
            .unauth_allowed = "NEVER",
            .unsecure_allowed = "NEVER",
            .ciphers = "GCM_AES_128",
            .cak = "12 34 56 78 9A BC DE F0 12 34 56 78 9A BC DE F0",
            .ckn = "12 34",
            .intf_mode = "DYNAMIC",
            .drv_macsec_mode  = "software",
            .mc_uart = nullptr,
            .phy_vlan_bypass  = nullptr,
            .phy_vlan_list    = nullptr,
            .phy_proto_bypass = nullptr,
            .phy_mac_bypass   = nullptr,
            .phy_transmit_sci = nullptr,
            .phy_transmit_mtu = nullptr,
        }
    };

    TempFile gen_file;

    char const* serialise(void) {
        static char buffer[8192];
        size_t p = 0U;

        p += sprintf(&buffer[p], "# Unit test configuration\n\n");
        p += sprintf(&buffer[p], "%s\n", log_level               .serialise("log_level: "));
        p += sprintf(&buffer[p], "%s\n", verbosity               .serialise("verbosity: "));
        p += sprintf(&buffer[p], "%s\n", hello_time              .serialise("hello_time: "));
        p += sprintf(&buffer[p], "%s\n", bounded_hello_time      .serialise("bounded_hello_time: "));
        p += sprintf(&buffer[p], "%s\n", life_time               .serialise("life_time: "));
        p += sprintf(&buffer[p], "%s\n", sak_retire_time         .serialise("sak_retire_time: "));
        p += sprintf(&buffer[p], "%s\n", hello_time_rampup       .serialise("hello_time_rampup: "));
        p += sprintf(&buffer[p], "%s\n", transmit_empty_dist_sak .serialise("transmit_empty_dist_sak: "));
        p += sprintf(&buffer[p], "%s\n", transmit_empty_sak_use  .serialise("transmit_empty_sak_use: "));
        p += sprintf(&buffer[p], "%s\n", transmit_null_xpn       .serialise("transmit_null_xpn: "));
        p += sprintf(&buffer[p], "%s\n", secy_polling_ms         .serialise("secy_polling_ms: "));
        p += sprintf(&buffer[p], "%s\n", raw_line                .serialise(""));

        if (interfaces[0].enable || interfaces[1].enable) {
            p += sprintf(&buffer[p], "\ninterfaces:\n");
            p += sprintf(&buffer[p], "%s\n", interfaces[0].serialise());
            p += sprintf(&buffer[p], "%s\n", interfaces[1].serialise());
        }

        return buffer;
    }

    char const* generate(void) {
        char const*cfg = serialise();
        FILE* cfg_file = fopen(gen_file, "wb");
        assert(cfg_file);
        fwrite(cfg, strlen(cfg), 1U, cfg_file);
        fclose(cfg_file);
        return gen_file;
    }
};

struct BasicTest : public ::testing::Test {
    CMocks mocks;
    Configuration configuration;
    char const* cfg_file;

    Configuration*const cfg = &configuration;
    Interface*const if0 = &cfg->interfaces[0];
    Interface*const if1 = &cfg->interfaces[1];

    t_MKA_config const*test_config = nullptr;

    virtual void SetUp(void) {
        EXPECT_CALL(mocks, MKA_DeriveKEK(_, _, _, _)) .WillRepeatedly(Return(true));
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("loaded CAK key"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_DeriveICK(_, _, _, _, _)) .WillRepeatedly(Return(true));
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("bytes as CKN"), _)) .Times(AnyNumber());
    }

    virtual void TearDown(void) {
        if (nullptr != test_config) {
            mka_config_free(const_cast<t_MKA_config*>(test_config)); // safe cast
            test_config = nullptr;
        }
    }

    t_MKA_config const* import(void) {
        if (nullptr != test_config) {
            mka_config_free(const_cast<t_MKA_config*>(test_config)); // safe cast
        }
        cfg_file = cfg->generate();
        return (test_config = mka_config_load(cfg_file));
    }

    void yaml_dump(void) {
        yaml_parser_t parser;
        yaml_event_t event;

        /* Create the Parser object. */
        yaml_parser_initialize(&parser);

        cfg_file = cfg->generate();
        FILE* f = fopen(cfg_file, "rb");
        ASSERT_THAT(f, Ne(nullptr));

        yaml_parser_set_input_file(&parser, f);

        bool done = false;
        bool error = false;
        
        /* Read the event sequence. */
        while (!done && !error) {
            if (!yaml_parser_parse(&parser, &event)) {
                EXPECT_TRUE(false) << "Error from parser @line " << parser.problem_mark.line << " col " << parser.problem_mark.column << "|" << parser.problem << "|" << parser.context;
                error = true;
                break;
            }

            print_event(&event);
            done = (event.type == YAML_STREAM_END_EVENT);
            yaml_event_delete(&event);
        }
        yaml_parser_delete(&parser);
    }
};

TEST_F(BasicTest, Cak128) {
    t_MKA_key my_cak = { { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 }, 16 };
    t_MKA_ckn my_ckn = { { 0x23, 0x45 }, 2 };
    t_MKA_key my_kek = { { 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44 }, 16 };
    t_MKA_key my_ick = { { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }, 16 };

    memcpy(if1, if0, sizeof(*if0));
    if1->cak = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
    if1->ckn = "23 45";

    EXPECT_CALL(mocks, MKA_DeriveKEK(ObjectMatch(my_cak), ObjectMatch(my_ckn), 16, _))
        .WillOnce(DoAll(MemcpyToArg<3>(&my_kek, sizeof(my_kek)), Return(true)));
    EXPECT_CALL(mocks, MKA_DeriveICK(MKA_ALGORITHM_AGILITY, ObjectMatch(my_cak), ObjectMatch(my_ckn), 16, _))
        .WillOnce(DoAll(MemcpyToArg<4>(&my_ick, sizeof(my_ick)), Return(true)));

    ASSERT_THAT(import(), Ne(nullptr));

    t_MKA_key cak;
    t_MKA_ckn ckn;
    t_MKA_key kek;
    t_MKA_key ick;

    ASSERT_THAT(MKA_RetrieveCAKCKN(1, &cak, &ckn), Eq(MKA_OK));
    ASSERT_THAT(cak, ObjectMatch(my_cak));
    ASSERT_THAT(ckn, ObjectMatch(my_ckn));

    ASSERT_THAT(MKA_RetrieveKEK(1, &kek), Eq(MKA_OK));
    ASSERT_THAT(kek, ObjectMatch(my_kek));

    ASSERT_THAT(MKA_RetrieveICK(1, &ick), Eq(MKA_OK));
    ASSERT_THAT(ick, ObjectMatch(my_ick));
}

TEST_F(BasicTest, Cak256) {
    t_MKA_key my_cak = { { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 }, 32 };
    t_MKA_ckn my_ckn = { { 0x23, 0x45 }, 2 };
    t_MKA_key my_kek = { { 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44,
                           0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44 }, 32 };
    t_MKA_key my_ick = { { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }, 32 };

    memcpy(if1, if0, sizeof(*if0));
    if1->cak = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
    if1->ckn = "23 45";

    EXPECT_CALL(mocks, MKA_DeriveKEK(ObjectMatch(my_cak), ObjectMatch(my_ckn), 32, _))
        .WillOnce(DoAll(MemcpyToArg<3>(&my_kek, sizeof(my_kek)), Return(true)));
    EXPECT_CALL(mocks, MKA_DeriveICK(MKA_ALGORITHM_AGILITY, ObjectMatch(my_cak), ObjectMatch(my_ckn), 32, _))
        .WillOnce(DoAll(MemcpyToArg<4>(&my_ick, sizeof(my_ick)), Return(true)));

    ASSERT_THAT(import(), Ne(nullptr));

    t_MKA_key cak;
    t_MKA_ckn ckn;
    t_MKA_key kek;
    t_MKA_key ick;

    ASSERT_THAT(MKA_RetrieveCAKCKN(1, &cak, &ckn), Eq(MKA_OK));
    ASSERT_THAT(cak, ObjectMatch(my_cak));
    ASSERT_THAT(ckn, ObjectMatch(my_ckn));

    ASSERT_THAT(MKA_RetrieveKEK(1, &kek), Eq(MKA_OK));
    ASSERT_THAT(kek, ObjectMatch(my_kek));

    ASSERT_THAT(MKA_RetrieveICK(1, &ick), Eq(MKA_OK));
    ASSERT_THAT(ick, ObjectMatch(my_ick));
}

TEST_F(BasicTest, Device) {
    if0->device.value = "qwerty";
    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(test_config->bus_config[0].port_name, MemoryWith<char>({'q', 'w', 'e', 'r', 't', 'y', '\0'}));
}

TEST_F(BasicTest, DeviceMacsec) {
    if0->device_macsec.value = "asdfgh";
    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(test_config->bus_config[0].controlled_port_name, MemoryWith<char>({'a', 's', 'd', 'f', 'g', 'h', '\0'}));
}

struct ImportErrors : public BasicTest { };

TEST_F(ImportErrors, BaseConfigurationWorks) {
    ASSERT_THAT(import(), Ne(nullptr));
}

TEST_F(ImportErrors, FileAccess) {
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("cannot open"), _));
    ASSERT_THAT(mka_config_load("/tmp/this_file_does_not_exist"), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidRoot) {
    cfg->log_level               = nullptr;
    cfg->verbosity               = nullptr;
    cfg->hello_time              = nullptr;
    cfg->bounded_hello_time      = nullptr;
    cfg->life_time               = nullptr;
    cfg->sak_retire_time         = nullptr;
    cfg->hello_time_rampup       = nullptr;
    cfg->transmit_empty_dist_sak = nullptr;
    cfg->transmit_empty_sak_use  = nullptr;
    cfg->transmit_null_xpn       = nullptr;
    cfg->secy_polling_ms         = nullptr;
    cfg->raw_line                = "[1,2,3]";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("mapping expected as root element"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, YamlParsingError) {
    cfg->raw_line = "///";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("YAML parsing error"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, MissingMandatoryGlobalParameter) {
    cfg->verbosity = nullptr;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("missing parameters: verbosity"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, MissingMandatoryInterfaceParameter) {
    if0->macsec = nullptr;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("missing parameters: macsec"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, NoInterfaces) {
    if0->enable = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("no interfaces configured"), _));
    /* yaml_dump(); */
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, NoHelloTimeRampUp) {
    cfg->hello_time_rampup = nullptr;
    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(test_config->global_config.hello_rampup_number, Eq(0));
}

TEST_F(ImportErrors, HelloTimeRampUp_StringList) {
    cfg->hello_time_rampup = "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20";
    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->global_config.hello_rampup_number, Eq(20));
    ASSERT_THAT(test_config->global_config.hello_rampup, Ne(nullptr));
    ASSERT_THAT(test_config->global_config.hello_rampup, MemoryWith<uint32_t>({
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
    }));
}

TEST_F(ImportErrors, HelloTimeRampUp_YamlList) {
    cfg->hello_time_rampup = "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]";
    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->global_config.hello_rampup_number, Eq(20));
    ASSERT_THAT(test_config->global_config.hello_rampup, Ne(nullptr));
    ASSERT_THAT(test_config->global_config.hello_rampup, MemoryWith<uint32_t>({
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
    }));
}

TEST_F(ImportErrors, HelloTimeRampUp_YamlList_InvalidScalar) {
    cfg->hello_time_rampup = "[1, 2, 3, 4, 5, 6, 7, 8, 9, [1, 0], 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expecting type SCALAR got type SEQUENCE_START"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, HelloTimeRampUp_UnexpectedType) {
    cfg->hello_time_rampup = "{a:b, c:d}";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expecting list or string with space-separated elements"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidInteger) {
    cfg->verbosity = "qwerty";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("integer casting error"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, IntegerOutOfRange) {
    cfg->verbosity = "5";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("out of range"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, BoolUnexpectedYamlType) {
    cfg->transmit_empty_dist_sak = "[1,2,3]";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expecting type SCALAR got type SEQUENCE_START"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, BoolOutOfRange) {
    cfg->transmit_empty_dist_sak = "aaaaaa";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, LogLevelUnexpectedYamlType) {
    cfg->log_level = "[1,2,3]";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expecting type SCALAR got type SEQUENCE_START"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, LogLevelOutOfRange) {
    cfg->log_level = "aaaaaa";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, RoleUnexpectedYamlType) {
    if0->role = "[1,2,3]";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expecting type SCALAR got type SEQUENCE_START"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, RoleOutOfRange) {
    if0->role = "aaaaaa";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, CipherOutOfRange) {
    if0->ciphers = "aaaaaa";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, CipherDuplicated) {
    if0->ciphers = "gcm_aes_256 gcm_aes_256";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("duplicated"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, AllCiphers) {
    if0->ciphers = "gcm_aes_128 gcm_aes_256 gcm_aes_xpn_128 gcm_aes_xpn_256 null";
    ASSERT_THAT(import(), Ne(nullptr));
}

TEST_F(ImportErrors, CakTooShort) {
    if0->cak = "11";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Invalid length"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, CakTooLong) {
    if0->cak = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("too long"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, CakByteOutOfRange) {
    if0->cak = "111 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("out of range"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, CakByteNonHex) {
    if0->cak = "pasta 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("casting error"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, CknTooShort) {
    if0->ckn = "";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("identifier is empty"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, CknValid) {
    if0->ckn = "98 76 54 32";
    ASSERT_THAT(import(), Ne(nullptr));
    t_MKA_key cak;
    t_MKA_ckn ckn;
    ASSERT_THAT(MKA_RetrieveCAKCKN(0, &cak, &ckn), Eq(MKA_OK));
    ASSERT_THAT(ckn.name, MemoryWith<uint8_t>({ 0x98, 0x76, 0x54, 0x32 }));
}

TEST_F(ImportErrors, CknTooLong) {
    if0->ckn = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("identifier too long"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMacsecMode) {
    if0->macsec = "qwerty";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, FormatErrorListInsteadOfScalar) {
    cfg->verbosity = "[1, 2, 3]";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expecting type SCALAR got type SEQUENCE_START"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, FormatErrorGlobalSettings) {
    cfg->raw_line = "[1,2,3] : 4";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expected sequence of scalar elements in global settings"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, FormatErrorInterfaceSettings) {
    if0->raw_line = "    [1,2,3] : 4";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("expected sequence of scalar elements in interface settings"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, DuplicatedGlobalSetting) {
    cfg->raw_line = "verbosity: 1";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("duplicated setting"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, UnrecognisedSetting) {
    cfg->raw_line = "qwerty: asdf";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("unrecognised configuration setting"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidUnauthAllowed) {
    if0->unauth_allowed = "qwerty";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidUnsecureAllowed) {
    if0->unsecure_allowed = "qwerty";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMacsecDriverMode) {
    if0->drv_macsec_mode = "qwerty";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidVlanBypass) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_vlan_bypass = "ZZZ";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("possible values"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidVlanBypassList) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_vlan_list = "ZZZ";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("integer casting error"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidVlanBypassList2) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_vlan_list = "1 2 3 ZZZ";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("integer casting error"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidVlanBypassListRangeMin) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_vlan_list = "1 2 3 0";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("out of range"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidVlanBypassListRangeMax) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_vlan_list = "1 2 3 4096";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("out of range"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidVlanTooMany) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_vlan_list = "1 2 3 4 5";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Too many bypass"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidProtoBypassList) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_proto_bypass = "ZZZ";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("integer casting error"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidProtoBypassListTooMany) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_proto_bypass = "1 2 3 4 5 6 7 8 9";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Too many bypass"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMACBypassList) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_mac_bypass = "qwerty";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Invalid MAC"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMACBypassList2) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_mac_bypass = "00:11:22:33:44";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Invalid MAC"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMACBypassList3) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_mac_bypass = "00:11:22:33:44:ZZ";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Invalid MAC"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMACBypassList4) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_mac_bypass = "00-11-22-33-44-55";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Invalid MAC"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMACBypassList5) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_mac_bypass = "00:11:22:33:44:55:zz";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Invalid MAC"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

TEST_F(ImportErrors, InvalidMACBypassListTooMany) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/dev/ttyUSB0";
    if0->phy_mac_bypass = "00:11:22:33:44:55 00:11:22:33:44:56 00:11:22:33:44:57 00:11:22:33:44:58 00:11:22:33:44:59 00:11:22:33:44:60 00:11:22:33:44:61 00:11:22:33:44:62 00:11:22:33:44:63 ";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Too many MAC"), _));
    ASSERT_THAT(import(), Eq(nullptr));
}

struct TestLogLevels : public BasicTest,
    public ::testing::WithParamInterface<std::tuple<char const*, uint8_t>>
{
    char const*encoded      = std::get<0>(GetParam());
    uint8_t expected        = std::get<1>(GetParam());
};

INSTANTIATE_TEST_SUITE_P(LogLevels, TestLogLevels, ::testing::Values(
    std::make_tuple("error",    MKA_LOGLEVEL_ERROR),
    std::make_tuple("warning",  MKA_LOGLEVEL_WARNING),
    std::make_tuple("info",     MKA_LOGLEVEL_INFO),
    std::make_tuple("debug",    MKA_LOGLEVEL_DEBUG)
));

TEST_P(TestLogLevels, Decode) {
    cfg->log_level = encoded;

    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(mka_active_log_level, Eq(expected)) << "test case: " << encoded;
}

struct TestVerbosityLevels : public BasicTest,
    public ::testing::WithParamInterface<std::tuple<char const*, uint8_t>>
{
    char const*encoded      = std::get<0>(GetParam());
    uint8_t expected        = std::get<1>(GetParam());
};

INSTANTIATE_TEST_SUITE_P(VerbosityLevels, TestVerbosityLevels, ::testing::Values(
    std::make_tuple("0",  0),
    std::make_tuple("1",  1),
    std::make_tuple("2",  2),
    std::make_tuple("3",  3)
));

TEST_P(TestVerbosityLevels, Decode) {
    cfg->verbosity = encoded;

    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(mka_active_log_verbosity, Eq(expected)) << "test case: " << encoded;
}

struct TestBoolLevels : public BasicTest,
    public ::testing::WithParamInterface<std::tuple<char const*, bool>>
{
    char const*encoded      = std::get<0>(GetParam());
    bool expected           = std::get<1>(GetParam());
};

INSTANTIATE_TEST_SUITE_P(BoolLevels, TestBoolLevels, ::testing::Values(
    std::make_tuple("on",       true),
    std::make_tuple("true",     true),
    std::make_tuple("off",      false),
    std::make_tuple("false",    false)
));

TEST_P(TestBoolLevels, Decode) {
    cfg->transmit_empty_dist_sak = encoded;

    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(test_config->global_config.transmit_empty_dist_sak, Eq(expected)) << "test case: " << encoded;
}

struct TestRoleLevels : public BasicTest,
    public ::testing::WithParamInterface<std::tuple<char const*, t_MKA_role>>
{
    char const*encoded      = std::get<0>(GetParam());
    t_MKA_role expected     = std::get<1>(GetParam());
};

INSTANTIATE_TEST_SUITE_P(RoleLevels, TestRoleLevels, ::testing::Values(
    std::make_tuple("auto",         MKA_ROLE_AUTO),
    std::make_tuple("key_server",   MKA_ROLE_FORCE_KEY_SERVER),
    std::make_tuple("key_client",   MKA_ROLE_FORCE_KEY_CLIENT)
));

TEST_P(TestRoleLevels, Decode) {
    if0->role = encoded;

    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(test_config->bus_config[0].kay.actor_role, Eq(expected)) << "test case: " << encoded;
}


struct TestCipherLevels : public BasicTest,
    public ::testing::WithParamInterface<std::tuple<char const*, uint64_t>>
{
    char const*encoded      = std::get<0>(GetParam());
    uint64_t expected       = std::get<1>(GetParam());
};

INSTANTIATE_TEST_SUITE_P(CipherLevels, TestCipherLevels, ::testing::Values(
    std::make_tuple("gcm_aes_128",          MKA_CS_ID_GCM_AES_128),
    std::make_tuple("gcm_aes_256",          MKA_CS_ID_GCM_AES_256),
    std::make_tuple("gcm_aes_xpn_128",      MKA_CS_ID_GCM_AES_XPN_128),
    std::make_tuple("gcm_aes_xpn_256",      MKA_CS_ID_GCM_AES_XPN_256),
    std::make_tuple("null",                 MKA_CS_NULL)
));

TEST_P(TestCipherLevels, Decode) {
    if0->ciphers = encoded;

    ASSERT_THAT(import(), Ne(nullptr));
    ASSERT_THAT(test_config->bus_config[0].impl.cipher_preference[0], Eq(expected)) << "test case: " << encoded;
}

struct TestMediaConverterSettings : public BasicTest { };

TEST_F(TestMediaConverterSettings, Disable) {
    if0->drv_macsec_mode = "mediaconverter";
    if0->mc_uart = "/asdf";
    if0->phy_vlan_bypass = "true";
    if0->phy_vlan_list = "0x10 0x11 50";
    if0->phy_proto_bypass = "0x1111";
    if0->phy_mac_bypass = "00:11:22:33:44:55 22:33:44:55:66:77";
    if0->phy_transmit_sci = "true";
    if0->phy_transmit_mtu = "23";

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("loaded"), _)) .Times(AnyNumber());
    ASSERT_THAT(import(), Ne(nullptr));

    EXPECT_THAT(test_config->bus_config[0].impl.mode,                           Eq(MKA_MACSEC_MEDIACONVERTER));
    EXPECT_THAT(test_config->bus_config[0].impl.mc_uart,                        MemoryWith<char>({'/', 'a', 's', 'd', 'f', '\0'}));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.vlan_bypass,       Eq(true));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.vlan[0],           Eq(0x10));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.vlan[1],           Eq(0x11));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.vlan[2],           Eq(50));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.vlan[3],           Eq(0));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.proto_bypass[0],   Eq(0x1111));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.proto_bypass[1],   Eq(0));

    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[0].address[0],   Eq(0x00));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[0].address[1],   Eq(0x11));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[0].address[2],   Eq(0x22));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[0].address[3],   Eq(0x33));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[0].address[4],   Eq(0x44));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[0].address[5],   Eq(0x55));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[0].enable,       Eq(true));

    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[1].address[0],   Eq(0x22));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[1].address[1],   Eq(0x33));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[1].address[2],   Eq(0x44));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[1].address[3],   Eq(0x55));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[1].address[4],   Eq(0x66));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[1].address[5],   Eq(0x77));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[1].enable,       Eq(true));

    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.DA_bypass[2].enable,       Eq(false));

    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.transmit_sci,      Eq(true));
    EXPECT_THAT(test_config->bus_config[0].impl.phy_settings.transmit_mtu,      Eq(23));
}

struct TestMacsecLevels : public BasicTest { };

TEST_F(TestMacsecLevels, Disable) {
    if0->macsec = "disable";

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("cipher GCM_AES_128 ignored, macsec is disabled"), _));
    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->bus_config[0].port_capabilities.macsec,    Eq(false));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_capable,          Eq(MKA_MACSEC_NOT_IMPLEMENTED));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_desired,          Eq(false));
    EXPECT_THAT(test_config->bus_config[0].impl.cipher_preference[0],   Eq(MKA_CS_NULL));
    EXPECT_THAT(test_config->bus_config[0].impl.conf_offset_preference, Eq(MKA_CONFIDENTIALITY_NONE));
}

TEST_F(TestMacsecLevels, Integrity) {
    if0->macsec = "integrity";

    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->bus_config[0].port_capabilities.macsec,    Eq(true));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_capable,          Eq(MKA_MACSEC_INTEGRITY));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_desired,          Eq(true));
    EXPECT_THAT(test_config->bus_config[0].impl.cipher_preference[0],   Ne(MKA_CS_NULL));
    EXPECT_THAT(test_config->bus_config[0].impl.conf_offset_preference, Eq(MKA_CONFIDENTIALITY_NONE));
}

TEST_F(TestMacsecLevels, Confidentiality_0) {
    if0->macsec = "conf_0";

    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->bus_config[0].port_capabilities.macsec,    Eq(true));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_capable,          Eq(MKA_MACSEC_INT_CONF_0));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_desired,          Eq(true));
    EXPECT_THAT(test_config->bus_config[0].impl.cipher_preference[0],   Ne(MKA_CS_NULL));
    EXPECT_THAT(test_config->bus_config[0].impl.conf_offset_preference, Eq(MKA_CONFIDENTIALITY_OFFSET_0));
}

TEST_F(TestMacsecLevels, Confidentiality_30) {
    if0->macsec = "conf_30";

    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->bus_config[0].port_capabilities.macsec,    Eq(true));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_capable,          Eq(MKA_MACSEC_INT_CONF_0_30_50));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_desired,          Eq(true));
    EXPECT_THAT(test_config->bus_config[0].impl.cipher_preference[0],   Ne(MKA_CS_NULL));
    EXPECT_THAT(test_config->bus_config[0].impl.conf_offset_preference, Eq(MKA_CONFIDENTIALITY_OFFSET_30));
}

TEST_F(TestMacsecLevels, Confidentiality_50) {
    if0->macsec = "conf_50";

    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->bus_config[0].port_capabilities.macsec,    Eq(true));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_capable,          Eq(MKA_MACSEC_INT_CONF_0_30_50));
    EXPECT_THAT(test_config->bus_config[0].kay.macsec_desired,          Eq(true));
    EXPECT_THAT(test_config->bus_config[0].impl.cipher_preference[0],   Ne(MKA_CS_NULL));
    EXPECT_THAT(test_config->bus_config[0].impl.conf_offset_preference, Eq(MKA_CONFIDENTIALITY_OFFSET_50));
}

struct TestUnauthAllowedValues : public BasicTest, public ::testing::WithParamInterface<std::tuple<char const*, t_MKA_unauth_allow>> { };

TEST_P(TestUnauthAllowedValues, TestUnauthValues) {
    if0->unauth_allowed = std::get<0>(GetParam());

    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->bus_config[0].logon_nid.unauth_allowed,  Eq(std::get<1>(GetParam())));
}

INSTANTIATE_TEST_SUITE_P(UnauthAllowedValues, TestUnauthAllowedValues, ::testing::Values(
    std::make_tuple("NEVER",     MKA_UNAUTH_NEVER),
    std::make_tuple("IMMEDIATE", MKA_UNAUTH_IMMEDIATE),
    std::make_tuple("AUTH_FAIL", MKA_UNAUTH_ON_AUTH_FAIL)
));

struct TestUnsecureAllowedValues : public BasicTest, public ::testing::WithParamInterface<std::tuple<char const*, t_MKA_unsec_allow>> { };

TEST_P(TestUnsecureAllowedValues, TestUnsecureValues) {
    if0->unsecure_allowed = std::get<0>(GetParam());

    ASSERT_THAT(import(), Ne(nullptr));
    EXPECT_THAT(test_config->bus_config[0].logon_nid.unsecure_allowed,  Eq(std::get<1>(GetParam())));
}

INSTANTIATE_TEST_SUITE_P(UnsecureAllowedValues, TestUnsecureAllowedValues, ::testing::Values(
    std::make_tuple("NEVER",     MKA_UNSECURE_NEVER),
    std::make_tuple("IMMEDIATE", MKA_UNSECURE_IMMEDIATE),
    std::make_tuple("MKA_FAIL",  MKA_UNSECURE_ON_MKA_FAIL),
    std::make_tuple("MKA_SERVER",MKA_UNSECURE_PER_MKA_SERVER)
));

#if 0 // this is just an example code to play with the library

TEST_F(BasicTest, Example_tests)
{
    yaml_parser_t parser;
    yaml_event_t event;

    /* Create the Parser object. */
    yaml_parser_initialize(&parser);

    FILE* f = fopen("../test.yml", "rb");
    ASSERT_THAT(f, Ne(nullptr));

    yaml_parser_set_input_file(&parser, f);

    bool done = false;
    bool error = false;
    
    /* Read the event sequence. */
    while (!done && !error) {

        /* Get the next event. */
        if (!yaml_parser_parse(&parser, &event)) {
            EXPECT_TRUE(false) << "Error from parser @line " << parser.problem_mark.line << " col " << parser.problem_mark.column << "|" << parser.problem << "|" << parser.context;
            error = true;
            break;
        }

        //printf("Event: %i: %s\n", event.type, ev2str[event.type]);
        print_event(&event);
        /*
          ...
          Process the event.
          ...
        */

        /* Are we finished? */
        done = (event.type == YAML_STREAM_END_EVENT);

        /* The application is responsible for destroying the event object. */
        yaml_event_delete(&event);

    }

    /* Destroy the Parser object. */
    yaml_parser_delete(&parser);
}
#endif

