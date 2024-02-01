/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: ut_kay_rx.cpp
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <arpa/inet.h>

#include "ut_helpers.h"
#include "mka_kay_internal.h"
#include "mocks.h"
#include "kay_helpers.h"


uint32_t mka_tick_time_ms = 555U;
t_MKA_global_config const* MKA_active_global_config = nullptr;
t_MKA_bus_config const* MKA_active_buses_config = nullptr;

struct PreInit : public KayTestBase {
    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    PreInit(void)
    {
    }

    void SetUp(void) {
        KayTestBase::SetUp(false);

        //EXPECT_CALL(mocks, MKA_l2_init(0, MKA_L2_PROTO_EAPOL)) .Times(1);
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received EAPOL message from"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Creating new participant MI"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cleaning up peer"), _)) .Times(AnyNumber());

        // Ignored, no SAK shall be installed at this point
        EXPECT_CALL(mocks, MKA_l2_init(0, 0x888E)) .WillRepeatedly(Return(MKA_OK));
        EXPECT_CALL(mocks, MKA_l2_getLocalAddr(0, _)) .WillRepeatedly(DoAll(MemcpyToArg<1>((void*)local_mac, 6), Return(MKA_OK)));
        EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetServerTransmitting(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetAllReceiving(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSC(0, ObjectMatch(ctx->actor_sci))) .WillRepeatedly(Return(&txsc));
    }
};

struct RxValidation : public KayTestBase {

    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    RxValidation(void)
    {
    }

    void SetUp(void) {
        KayTestBase::SetUp(false);

        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received EAPOL message from"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Creating new participant MI"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cleaning up peer"), _)) .Times(AnyNumber());

        // transmission (which is ignored at this point) may trigger this calls
        EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, _, _, _, _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, _, _, _, _)) .Times(AnyNumber());

        //EXPECT_CALL(mocks, MKA_l2_init(0, MKA_L2_PROTO_EAPOL)) .Times(1);
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received EAPOL message from"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Creating new participant MI"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cleaning up peer"), _)) .Times(AnyNumber());

        // Ignored, no SAK shall be installed at this point
        EXPECT_CALL(mocks, MKA_l2_init(0, 0x888E)) .WillOnce(Return(MKA_OK));
        EXPECT_CALL(mocks, MKA_l2_getLocalAddr(0, _)) .WillRepeatedly(DoAll(MemcpyToArg<1>((void*)local_mac, 6), Return(MKA_OK)));
        EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetServerTransmitting(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetAllReceiving(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSC(0, ObjectMatch(ctx->actor_sci))) .WillOnce(Return(&txsc));
        MKA_KAY_Init(0);

        EXPECT_CALL(mocks, print_action(LoggingMessageContains("KAY enabled"), _)) .Times(1);
        EXPECT_CALL(mocks, MKA_LOGON_SetKayEnabled(0, _));
        EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
        EXPECT_THAT(MKA_KAY_GetEnable(0), Eq(false));
        MKA_KAY_SetEnable(0, true);
        EXPECT_THAT(MKA_KAY_GetEnable(0), Eq(false));
        MKA_KAY_MainFunctionTimers(0U);
        EXPECT_THAT(MKA_KAY_GetEnable(0), Eq(true));

        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Creating participant."), _)) .Times(1);
        //EXPECT_CALL(mocks, MKA_LOGON_SignalCreatedMKA(_,_,_,_,_,_,_));
        EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0U, MKA_PENDING));
        MKA_KAY_CreateMKA(0, &ckn, &cak, &kek, &ick, nullptr, MKA_TIMER_MAX);

        // disable transmission!
        ctx->new_info = false;
        mka_timer_stop(&participant->hello);
        // even if it transmits, ignore
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Could not generate ICV for MKPDU"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_ComputeICV(
                /* alg. ag  */  MKA_ALGORITHM_AGILITY,
                /* ICK      */  &mka_kay[0].participant.ick,
                /* message  */  Not(MemoryWith<uint8_t>(frame, 20U)),
                /* length   */  _,
                /* ICV      */  _
            )) .WillRepeatedly(Return(false));

        // Simulate one frame transmitted
        participant->mn = 1U;
    }
};

struct RxBasicParmSet : public RxValidation {

    RxBasicParmSet(void) {
    }

    void SetUp(void) {
        RxValidation::SetUp();
    }
};

struct RxPeerList : public RxValidation,
        public ::testing::WithParamInterface<uint32_t>  {
    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &lpeers, &ppeers, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    GenericPeerList* peers = nullptr;

    void SetUp(void) {
        RxValidation::SetUp();

        GenericPeerList*const which_one[2] = {
            /* 0 */ (GenericPeerList*)&ppeers,
            /* 1 */ (GenericPeerList*)&lpeers
        };
        peers = which_one[GetParam()];

        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(AnyNumber());

        lpeers.present_ = false;
        ppeers.present_ = false;
    }
};

INSTANTIATE_TEST_SUITE_P(RepeatRxLiveAndPotential, RxPeerList, ::testing::Values(0, 1));

struct RxSakUse : public RxValidation {
    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &lpeers, &sakuse, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    void SetUp(void) {
        RxValidation::SetUp();

        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);

        sakuse.present_ = false;
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
        EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
        EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
        EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self"), _)) .Times(1);

        EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 16), Return(true)));
        EXPECT_CALL(mocks, MKA_DeriveSAK(_, _, _, _, _, _, _)) .WillOnce(DoAll(MemcpyToArg<6>((void*)&sak, sizeof(sak)), Return(true)));
        EXPECT_CALL(mocks, MKA_CP_SetCipherSuite(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetCipherOffset(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedKI(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, _));
        EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0));
        EXPECT_CALL(mocks, MKA_SECY_InstallKey(0, _, _, true, true)) .WillOnce(Return((void*)12345));
        EXPECT_CALL(mocks, MKA_WrapKey(_, _, _)) .WillOnce(Return(true));

        // This can result in frame transmission, make it fail in a controlled way (we're not testing transmission, it's just noise)!
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Could not generate ICV for MKPDU"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_ComputeICV(
                /* alg. ag  */  MKA_ALGORITHM_AGILITY,
                /* ICK      */  &mka_kay[0].participant.ick,
                /* message  */  Not(MemoryWith<uint8_t>(frame, 20U)),
                /* length   */  _,
                /* ICV      */  _
            )) .WillRepeatedly(Return(false));
        
        FeedFrame(/*serialise*/true, /*handle_icv*/true);

        sakuse.present_ = true;
    }
};

struct RxXPN : public RxValidation {
    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &lpeers, &sakuse, &ann, &xpn, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    void SetUp(void) {
        test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256;
        test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_XPN_128;
        ann.present_ = true;
        ann.resetCiphers();
        ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_XPN_256);
        RxValidation::SetUp();

        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);

        sakuse.present_ = false;
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
        EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
        EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
        EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self"), _)) .Times(1);

        EXPECT_CALL(mocks, MKA_GetRandomBytes(32, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(true)));
        EXPECT_CALL(mocks, MKA_DeriveSAK(_, _, _, _, _, _, _)) .WillOnce(DoAll(MemcpyToArg<6>((void*)&sak, sizeof(sak)), Return(true)));
        EXPECT_CALL(mocks, MKA_CP_SetCipherSuite(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetCipherOffset(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedKI(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, _));
        EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0));
        EXPECT_CALL(mocks, MKA_SECY_InstallKey(0, _, _, true, true)) .WillOnce(Return((void*)12345));
        EXPECT_CALL(mocks, MKA_WrapKey(_, _, _)) .WillOnce(Return(true));

        // This can result in frame transmission, make it fail in a controlled way (we're not testing transmission, it's just noise)!
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Could not generate ICV for MKPDU"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_ComputeICV(
                /* alg. ag  */  MKA_ALGORITHM_AGILITY,
                /* ICK      */  &mka_kay[0].participant.ick,
                /* message  */  Not(MemoryWith<uint8_t>(frame, 20U)),
                /* length   */  _,
                /* ICV      */  _
            )) .WillRepeatedly(Return(false));
        
        FeedFrame(/*serialise*/true, /*handle_icv*/true);

        sakuse.present_ = true;
        xpn.present_ = true;
    }
};

struct RxDistSak : public RxValidation {
    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &lpeers, &sakuse, &distsak, &ann, &xpn, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    void SetUp(void) {
        RxValidation::SetUp();
        // Peer is key server now
        bps.key_server_ = true;
        bps.priority_ = 100U; // < 128U hence peer is now key server

        // This calls belong to other tests, we don't care now
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, false)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected peer as key server"), _)) .Times(AnyNumber());
        //EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair"), _)) .Times(1);

        // Prepare unknown key
        memset(sakuse.omi_, 0, sizeof(sakuse.omi_));
        memcpy(sakuse.lmi_, bps.mi_, sizeof(bps.mi_));
        sakuse.lmn_ = 23U;
        memcpy(participant->current_sak.identifier.mi, bps.mi_, sizeof(bps.mi_));
        participant->current_sak.identifier.kn = 22U;
        participant->current_sak.association_number = 1U;
        distsak.keynum_ = 23U;

        sakuse.present_ = false;
    }
};

struct CipherSuiteNegotiation : public RxValidation {
    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &lpeers, &sakuse, &distsak, &ann, &xpn, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    uint8_t sak_wrapped[40U];

    void SetUp(void) {
        RxValidation::SetUp();
        // Peer is key server now
        bps.key_server_ = false;
        bps.priority_ = 255U; // > 128U hence peer is now key client

        // This calls belong to other tests, we don't care now
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self as key server"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(AnyNumber());

        //EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair"), _)) .Times(1);

        sakuse.present_ = false;
        distsak.present_ = false;
    }

    void ExpectServerToAttemptSakTransmission(uint64_t ciphersuite, t_MKA_confidentiality_offset offset) {
        EXPECT_CALL(mocks, MKA_CP_SetCipherSuite(0, ciphersuite));
        EXPECT_CALL(mocks, MKA_CP_SetCipherOffset(0, offset));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedKI(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, _));
        EXPECT_CALL(mocks, MKA_DeriveSAK(_, _, _, _, 1, _, _)) .WillOnce(DoAll(MemcpyToArg<6>((void*)&sak, sizeof(sak)), Return(true)));
        EXPECT_CALL(mocks, MKA_GetRandomBytes(AnyOf(Eq(32), Eq(16)), _))
                .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(true)));
        EXPECT_CALL(mocks, MKA_SECY_InstallKey(0, _, _, true, true)) .WillOnce(Return((void*)12345));
        EXPECT_CALL(mocks, MKA_WrapKey(_, _, _)) .WillOnce(DoAll(
                MemcpyToArg<2>(sak_wrapped, 40U),
                Return(true))
        );
        EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0));

        HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);
    }
};

TEST_F(PreInit, MetaTest)
{
}

TEST_F(PreInit, ProtectFramesGetter)
{
    participant->advertise_macsec_capability = MKA_MACSEC_NOT_IMPLEMENTED;
    EXPECT_THAT(MKA_KAY_GetProtectFrames(0), Eq(false));

    participant->advertise_macsec_capability = MKA_MACSEC_INTEGRITY;
    EXPECT_THAT(MKA_KAY_GetProtectFrames(0), Eq(true));

    participant->advertise_macsec_capability = MKA_MACSEC_INT_CONF_0;
    EXPECT_THAT(MKA_KAY_GetProtectFrames(0), Eq(true));

    participant->advertise_macsec_capability = MKA_MACSEC_INT_CONF_0_30_50;
    EXPECT_THAT(MKA_KAY_GetProtectFrames(0), Eq(true));
}

TEST_F(PreInit, ValidateFramesGetter)
{
    participant->advertise_macsec_capability = MKA_MACSEC_NOT_IMPLEMENTED;
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0), Eq(MKA_VALIDATE_DISABLED));

    participant->advertise_macsec_capability = MKA_MACSEC_INTEGRITY;
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0), Eq(MKA_VALIDATE_STRICT));

    participant->advertise_macsec_capability = MKA_MACSEC_INT_CONF_0;
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0), Eq(MKA_VALIDATE_STRICT));

    participant->advertise_macsec_capability = MKA_MACSEC_INT_CONF_0_30_50;
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0), Eq(MKA_VALIDATE_STRICT));
}

TEST_F(PreInit, ReplayProtection)
{
    test_buses_active_config.kay.replay_protect = true;
    MKA_KAY_Init(0);
    EXPECT_THAT(MKA_KAY_GetReplayProtect(0), Eq(true));

    test_buses_active_config.kay.replay_protect = false;
    MKA_KAY_Init(0);
    EXPECT_THAT(MKA_KAY_GetReplayProtect(0), Eq(false));
}

TEST_F(PreInit, ReplayWindow)
{
    test_buses_active_config.kay.replay_protect_wnd = 123;
    MKA_KAY_Init(0);
    EXPECT_THAT(MKA_KAY_GetReplayWindow(0), Eq(123));

    test_buses_active_config.kay.replay_protect_wnd = 7654321;
    MKA_KAY_Init(0);
    EXPECT_THAT(MKA_KAY_GetReplayWindow(0), Eq(7654321));
}

TEST_F(PreInit, MacsecDisable0)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_NULL;
    MKA_KAY_Init(0);
    EXPECT_THAT(ctx->macsec_capable, Eq(MKA_MACSEC_NOT_IMPLEMENTED));
    EXPECT_THAT(ctx->macsec_replay_protect, Eq(false));
    EXPECT_THAT(ctx->macsec_replay_window, Eq(0U));
    EXPECT_THAT(ctx->macsec_delay_protect, Eq(false));
}

TEST_F(PreInit, MacsecDisable1)
{
    test_buses_active_config.kay.macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
    MKA_KAY_Init(0);
    EXPECT_THAT(ctx->macsec_capable, Eq(MKA_MACSEC_NOT_IMPLEMENTED));
    EXPECT_THAT(ctx->macsec_replay_protect, Eq(false));
    EXPECT_THAT(ctx->macsec_replay_window, Eq(0U));
    EXPECT_THAT(ctx->macsec_delay_protect, Eq(false));
}

TEST_F(PreInit, TransmitSecureChannelFails)
{
    EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSC(0, _)) .WillOnce(Return(nullptr));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("SecY returned NULL Transmit Secure Channel"), _)) .Times(1);
    MKA_KAY_Init(0);
}

TEST_F(RxValidation, MetaTest)
{
}

TEST_F(RxValidation, ChannelDisabled)
{
    ctx->enable = false;
    EXPECT_CALL(mocks, MKA_l2_receive(_, _, _)) .WillOnce(Return(MKA_NOT_OK));
    MKA_KAY_MainFunctionReception(0U);

    MKA_KAY_MainFunctionTransmission(0U);
    t_MKA_bus_info info;
    ASSERT_THAT(MKA_KAY_GetBusInfo(0U, &info), Eq(MKA_OK));
    ASSERT_THAT(info.status, Eq(MKA_STATUS_UNDEFINED));
}

TEST_F(RxValidation, NoMultipleParticipants)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Attempt to create a second participant."), _)) .Times(1);
    MKA_KAY_CreateMKA(0, &ckn, &cak, &kek, &ick, nullptr, MKA_TIMER_MAX);
}

TEST_F(RxValidation, NoFrame)
{
    EXPECT_CALL(mocks, MKA_l2_receive(0, _, MemoryWith<uint32_t>({MKA_EAPOL_MAX_SIZE})))
        .WillOnce(Return(MKA_NOT_OK));
    mka_receive_from_l2(0U);
}

TEST_F(RxValidation, ActorDisabled)
{
    mka_kay[0].participant.enable = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("no actor enabled"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);

    t_MKA_bus_info info;
    ASSERT_THAT(MKA_KAY_GetBusInfo(0U, &info), Eq(MKA_OK));
    ASSERT_THAT(info.status, Eq(MKA_STATUS_WAITING_PEER_LINK));
}

TEST_F(RxValidation, UnhandledEthertype)
{
    ethhdr.type_ = 0U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("unhandled ethertype"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, FrameTooShortForEAPOL)
{
    composition[1] = nullptr;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("frame too short"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, InvalidEAPOLVersion)
{
    eapol.version_ = 2U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("only version 3"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, FrameTooShortForMKA)
{
    force_mkpdu_len = 100U;
    composition[3] = nullptr;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received truncated MKPDU"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, NonMKAPdu)
{
    frame[15] = 0U;
    eapol.type_ = 0U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("non-MKA PDU"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, IndividualTargetAddress)
{
    ethhdr.dst_.addr[0] = 0U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("addressed to individual address"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, MKPDULessThan32Octets)
{
    force_mkpdu_len = 31U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU less than 32 octets"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, MKPDUNonMultipleOf4)
{
    force_mkpdu_len = 33U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("non-multiple of 4"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, CKNTooShort)
{
    bps.ckn_ = "";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with no CKN"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, CKNTooLarge)
{
    bps.ckn_ = "this ckn is too long long long lo";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with CKN too large"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, ICVdoesNotFit)
{
    bps.ckn_ = "this ckn is just fine fine fine ";
    icv.present_ = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("length smaller than BasicParameterSet + ICV"), _)) .Times(2);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);

    frame_size += 12U;
    FeedFrame(/*serialise*/false, /*handle_icv*/false);
}

TEST_F(RxValidation, UnsupportedVersion)
{
    bps.version_ = 99U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with unsupported version 99"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, CKNNameMismatch_1)
{
    bps.ckn_ = "abc";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with different CKN length."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, CKNNameMismatch_2)
{
    bps.ckn_ = "zz";
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with different CKN."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, AlgorithmAgilityMismatch)
{
    bps.algo_ = 0xFFU;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with unexpected Algorithm Agility."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);

    t_MKA_bus_info info;
    ASSERT_THAT(MKA_KAY_GetBusInfo(0U, &info), Eq(MKA_OK));
    ASSERT_THAT(info.status, Eq(MKA_STATUS_WAITING_PEER));
}

TEST_F(RxValidation, ICVwithIndication_CalculationError)
{
    EXPECT_CALL(mocks, MKA_ComputeICV(_, _, _, _, _)) .WillOnce(Return(false));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot compute ICV"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, ICVwithIndication_CalculationMismatch)
{
    uint8_t ICV[MKA_ICV_LENGTH];
    memcpy(ICV, icv.icv_, MKA_ICV_LENGTH);
    ICV[15] = 0xFF ^ ICV[15];
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  MemoryWith<uint8_t>(frame, 74U),
            /* length   */  74U - MKA_ICV_LENGTH,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(ICV, MKA_ICV_LENGTH),
                Return(true)
        ));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with invalid ICV"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);

    t_MKA_bus_info info;
    ASSERT_THAT(MKA_KAY_GetBusInfo(0U, &info), Eq(MKA_OK));
    ASSERT_THAT(info.status, Eq(MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER));
}

TEST_F(RxValidation, ICVwithIndication_CalculationOk)
{
    uint8_t ICV[MKA_ICV_LENGTH];
    memcpy(ICV, icv.icv_, MKA_ICV_LENGTH);
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  MemoryWith<uint8_t>(frame, 74U),
            /* length   */  74U - MKA_ICV_LENGTH,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(ICV, MKA_ICV_LENGTH),
                Return(true)
        ));
    memcpy(&participant->mi, bps.mi_, 12);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MI that collides"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, WithL2TrailingBytes_CalculationOk)
{
    uint8_t ICV[MKA_ICV_LENGTH];
    memcpy(ICV, icv.icv_, MKA_ICV_LENGTH);
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  MemoryWith<uint8_t>(frame, 74U),
            /* length   */  74U - MKA_ICV_LENGTH,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(ICV, MKA_ICV_LENGTH),
                Return(true)
        ));
    memcpy(&participant->mi, bps.mi_, 12);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MI that collides"), _)) .Times(1);
    serialise();

            // append trailing bytes at the end, MKA should still be able to work
            for(int n=0U; n<16U; ++n) {
                frame[frame_size++] = 0U;
            }
    FeedFrame(/*serialise*/false, /*handle_icv*/false);
}

TEST_F(RxValidation, ICVwithoutIndication_CalculationMismatch)
{
    uint8_t ICV[MKA_ICV_LENGTH];
    icv.indication_ = false;
    memcpy(ICV, icv.icv_, MKA_ICV_LENGTH);
    ICV[0] = 0xFF ^ ICV[0];
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  MemoryWith<uint8_t>(frame, 70U),
            /* length   */  70U - MKA_ICV_LENGTH,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(ICV, MKA_ICV_LENGTH),
                Return(true)
        ));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with invalid ICV"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, ICVwithoutIndication_CalculationOk)
{
    uint8_t ICV[MKA_ICV_LENGTH];
    icv.indication_ = false;
    memcpy(ICV, icv.icv_, MKA_ICV_LENGTH);
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  MemoryWith<uint8_t>(frame, 70U),
            /* length   */  70U - MKA_ICV_LENGTH,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(ICV, MKA_ICV_LENGTH),
                Return(true)
        ));
    memcpy(&participant->mi, bps.mi_, 12);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MI that collides"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}

TEST_F(RxValidation, ICVwithIndication_CalculationOk_RestOfFrameDiscarded)
{
    uint8_t ICV[MKA_ICV_LENGTH];
    memcpy(ICV, icv.icv_, MKA_ICV_LENGTH);
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  MemoryWith<uint8_t>(frame, 74U),
            /* length   */  74U - MKA_ICV_LENGTH,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(ICV, MKA_ICV_LENGTH),
                Return(true)
        ));
    memcpy(&participant->mi, bps.mi_, 12);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MI that collides"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/false);
}


TEST_F(RxBasicParmSet, MetaTest)
{
}

TEST_F(RxBasicParmSet, PeerKeyServerIgnored)
{
    ctx->role = MKA_ROLE_FORCE_KEY_SERVER;
    bps.key_server_ = true;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Configured as Key Server, received packet from a Key Server."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Eq(MKA_PEER_POTENTIAL));
}

TEST_F(RxBasicParmSet, PeerKeyClientIgnored)
{
    ctx->role = MKA_ROLE_FORCE_KEY_CLIENT;
    bps.key_server_ = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Configured as non Key Server, received packet from a non Key Server."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Eq(MKA_PEER_POTENTIAL));
}

TEST_F(RxBasicParmSet, MICollision_DifferentSCI)
{
    memcpy(&participant->mi, bps.mi_, 12);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MI that collides"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Eq(MKA_PEER_NONE));
}

TEST_F(RxBasicParmSet, MICollision_SameSCI)
{
    memcpy(&participant->mi, bps.mi_, 12);
    memcpy(&bps.sci_, &ctx->actor_sci, 16);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received MKPDU with our own SCI address"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, true)) .Times(0); // NO reset
    EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, true)) .Times(0); // NO reset
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Eq(MKA_PEER_NONE)); // drop effect
}

TEST_F(RxBasicParmSet, NewPotentialPeer)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    ASSERT_THAT(peer->mn, Eq(0x10A));
    ASSERT_THAT(peer->mi, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
    ASSERT_THAT(reinterpret_cast<uint8_t const*>(peer->sci.addr), MemoryWith<uint8_t>(bps.sci_.addr, 6));
    ASSERT_THAT(peer->sci.port, bps.sci_.port);
    ASSERT_THAT(peer->key_server, Eq(0));
    ASSERT_THAT(peer->macsec_desired, Eq(1));
    ASSERT_THAT(peer->macsec_capability, Eq(2));
    ASSERT_THAT(peer->compatible_capability, Eq(2));
    ASSERT_THAT(peer->state, Eq(MKA_PEER_POTENTIAL));
    ASSERT_THAT(peer->expiry.expiry, Eq(mka_tick_time_ms + MKA_active_global_config->life_time));

    t_MKA_bus_info info;
    ASSERT_THAT(MKA_KAY_GetBusInfo(0U, &info), Eq(MKA_OK));
    ASSERT_THAT(info.status, Eq(MKA_STATUS_IN_PROGRESS));
}

TEST_F(RxBasicParmSet, PeerWithDifferentSciDiscarded)
{
    memcpy(&peer->sci, &bps.sci_, 8);
    memcpy(&peer->mi, &bps.mi_, sizeof(bps.mi_));
    peer->state = MKA_PEER_POTENTIAL;
    bps.sci_.addr[0] ^= 0xFF;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("different SCI, but peer slot is occupied."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxBasicParmSet, PeerWithDifferentMiDiscarded)
{
    memcpy(&peer->sci, &bps.sci_, 8);
    memcpy(&peer->mi, &bps.mi_, sizeof(bps.mi_));
    peer->state = MKA_PEER_POTENTIAL;
    bps.mi_[1] ^= 0xFFU;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("same SCI, different MI, but peer slot is occupied."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxBasicParmSet, PeerWithMnRepeated)
{
    memcpy(&peer->sci, &bps.sci_, 8);
    memcpy(&peer->mi, &bps.mi_, sizeof(bps.mi_));
    peer->state = MKA_PEER_POTENTIAL;
    peer->mn = 0x10A;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKPDU with lower MN than expected."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxBasicParmSet, PeerWithMnInSequence)
{
    memcpy(&peer->sci, &bps.sci_, 8);
    memcpy(&peer->mi, &bps.mi_, sizeof(bps.mi_));
    peer->state = MKA_PEER_POTENTIAL;
    peer->mn = 0x109;
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}


TEST_P(RxPeerList, MetaTest)
{
}

TEST_P(RxPeerList, InvalidPeerListBodySize)
{
    peers->present_ = true;
    peers->invalid_sz_ = 15U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("peer list length not multiple"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Ne(MKA_PEER_LIVE));
}

TEST_P(RxPeerList, EmptyPeerListBodySize)
{
    peers->present_ = true;
    peers->number_ = 0U;
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Ne(MKA_PEER_LIVE));
}

TEST_P(RxPeerList, ListWithDifferentMI)
{
    peers->present_ = true;
    peers->mi_[0] ^= 0xFF;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("peer list with different MI"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Ne(MKA_PEER_LIVE));
}

TEST_P(RxPeerList, ListWithSameMIandFutureMN)
{
    peers->present_ = true;
    peers->mn_ = 1000;
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MN not emitted yet. Selecting new MI"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Ne(MKA_PEER_LIVE));
}

TEST_P(RxPeerList, ListWithSameMIbutNotRecentMN)
{
    peers->present_ = true;
    peers->mn_ = 1;
    participant->mn = 1000;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("my MI but very old MN"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Ne(MKA_PEER_LIVE));
}

TEST_P(RxPeerList, PeerTransitionToLiveInstallSAK)
{
    peers->present_ = true;
    peers->mn_ = 999;
    participant->mn = 1000;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self"), _)) .Times(1);

#if 1 // boah... it's more maintainable to make it fail here than handle all that will happen in the future
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(false)));
#else
    //EXPECT_CALL(mocks, MKA_DeriveSAK(_, _, _, _, _, _, _)) .WillOnce(DoAll(MemcpyToArg<6>((void*)&sak, sizeof(sak)), Return(true)));
    EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0));
    EXPECT_CALL(mocks, MKA_SECY_InstallKey(0, _, _, true, true));
    EXPECT_CALL(mocks, MKA_WrapKey(_, _, _)) .WillOnce(Return(true));
#endif

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Eq(MKA_PEER_LIVE));

    t_MKA_bus_info info;
    ASSERT_THAT(MKA_KAY_GetBusInfo(0U, &info), Eq(MKA_OK));
    ASSERT_THAT(info.status, Eq(MKA_STATUS_IN_PROGRESS));
}

TEST_F(RxSakUse, MetaTest)
{
}

TEST_F(RxSakUse, NonLivePeer)
{
    lpeers.present_ = false;
    peer->state = MKA_PEER_POTENTIAL;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("SAK USE from non-live peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, EmptyBodyMacsecNotSupported)
{
    sakuse.empty_ = true;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer does not support MACSEC"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, InvalidSize)
{
    sakuse.invalid_sz_ = 1U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("incorrect SAK USE body_len"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    sakuse.invalid_sz_ = 39U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("incorrect SAK USE body_len"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, UnknownKeys)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_));
    memset(sakuse.lmi_, 0, sizeof(sakuse.lmi_));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("SAK USE with no known key"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, OldAssociationNumberMismatch)
{
    sakuse.oan_ = 2;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("OAN not matching our key"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, LatestAssociationNumberMismatch)
{
    sakuse.lan_ = 2;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("LAN not matching our key"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, OldPacketNumberIsZero)
{
    sakuse.opn_ = 0;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("0 as Old Key Lowest Acceptable PN"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, LatestPacketNumberIsZero)
{
    sakuse.lpn_ = 0;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("0 as Latest Key Lowest Acceptable PN"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, DistributedSakLearntByPeer)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.lrx_ = true; // Indicate we are receiving with this key
    EXPECT_CALL(mocks, MKA_CP_SetAllReceiving(0, true));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer is now receiving with distributed SAK"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, ServerIsTransmittingWithNewSak)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.ltx_ = true; // Indicate we are receiving with this key
    participant->is_key_server = false;
    bps.key_server_ = true;
    EXPECT_CALL(mocks, MKA_CP_SetServerTransmitting(0, true));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Key Server is now transmitting with new SAK"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, NewPacketNumberLearnt_KeyActive)
{
    memset(sakuse.lmi_, 0, sizeof(sakuse.lmi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.opn_ = 0x11223344U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(participant->current_sak.next_pn, Eq(0x11223344U));
}

TEST_F(RxSakUse, NewPacketNumberLearnt_KeyInTransition)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.lpn_ = 0x11223344U;
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(participant->new_sak.next_pn, Eq(0x11223344U));
}


TEST_F(RxSakUse, PacketNumberExhaustion)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.lpn_ = 0xC0000000U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer reached PN exhaustion"), _)) .Times(1);

    // This action only happens in an attempt from kay to regenerate MI...
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(false)));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxSakUse, SA_Active_DelayProtect_KeyInTransition)
{
    {// Prepare an active SECY security association
        //EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSC(0, _)) .WillOnce(Return(&txsc));
        EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSC(0, _)) .WillOnce(Return(&rxsc));
        EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSA(0, 1, 1, _, _, _)) .WillOnce(Return(&txsa));
        EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSA(0, 1, 1, _, _)) .WillOnce(Return(&rxsa));
        MKA_KAY_CreateSAs(0, &participant->new_sak.identifier);

        EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_EnableReceive(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, true)) .Times(1);
        MKA_KAY_EnableReceiveSAs(0, &participant->new_sak.identifier);

        EXPECT_CALL(mocks, MKA_SECY_TransmitSA_EnableTransmit(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, true)) .Times(1);
        MKA_KAY_EnableTransmitSA(0, &participant->new_sak.identifier);

        ASSERT_THAT(participant->new_sak.transmits, Eq(true));
        ASSERT_THAT(participant->new_sak.receives, Eq(true));
    }

    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.delay_prot_ = true;
    sakuse.lpn_ = 0x11223344U;
    EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_UpdateNextPN(0, participant->new_sak.rxsa, 0x11223344U));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(participant->new_sak.next_pn, Eq(0x11223344U));
}

TEST_F(RxSakUse, SA_Active_DelayProtect_KeyActive)
{
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));

    {// Prepare an active SECY security association
        //EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSC(0, _)) .WillOnce(Return(&txsc));
        EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSC(0, _)) .WillOnce(Return(&rxsc));
        EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSA(0, 1, 1, _, _, _)) .WillOnce(Return(&txsa));
        EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSA(0, 1, 1, _, _)) .WillOnce(Return(&rxsa));
        MKA_KAY_CreateSAs(0, &participant->current_sak.identifier);

        EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_EnableReceive(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, true)) .Times(1);
        MKA_KAY_EnableReceiveSAs(0, &participant->current_sak.identifier);

        EXPECT_CALL(mocks, MKA_SECY_TransmitSA_EnableTransmit(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, true)) .Times(1);
        MKA_KAY_EnableTransmitSA(0, &participant->current_sak.identifier);

        ASSERT_THAT(participant->current_sak.transmits, Eq(true));
        ASSERT_THAT(participant->current_sak.receives, Eq(true));
    }

    memset(sakuse.lmi_, 0, sizeof(sakuse.lmi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.delay_prot_ = true;
    sakuse.opn_ = 0x11223344U;
    EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_UpdateNextPN(0, participant->current_sak.rxsa, 0x11223344U));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(participant->current_sak.next_pn, Eq(0x11223344U));
}

TEST_F(RxXPN, MetaTest)
{
}

TEST_F(RxXPN, ErrorNonLivePeer)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    peer->state = MKA_PEER_NONE;
    lpeers.present_ = false;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received XPN from non-live peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxXPN, ErrorInvalidLength_7)
{
    xpn.invalid_sz_ = 7;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer transmitting XPN parameter smaller than minimum of 8 bytes"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxXPN, DebugMessageNoXPN)
{
    participant->cipher = MKA_CS_ID_GCM_AES_256;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer transmits XPN, but XPN cipher is not being used. Silently ignored"), _)) .Times(1);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxXPN, IgnoredWithNoXpnCipher)
{
    participant->cipher = MKA_CS_ID_GCM_AES_256;

    xpn.l_hpn = 0x11112222U;
    xpn.o_hpn = 0x33334444U;

    memset(sakuse.lmi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.delay_prot_ = true;
    sakuse.opn_ = 0x11223344U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));
    participant->current_sak.rxsa = &rxsa;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer transmits XPN, but XPN cipher is not being used. Silently ignored"), _)) .Times(1);

    // Expecting SCI reporting ignoring extended packet number
    EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_UpdateNextPN(0U, participant->current_sak.rxsa, 0x3333444411223344ULL)) .Times(0);
    EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_UpdateNextPN(0U, participant->current_sak.rxsa, 0x11223344ULL)) .Times(1);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    // Internally storing without extended packet number
    ASSERT_THAT(participant->current_sak.next_pn, Eq(0x11223344ULL));
}

TEST_F(RxXPN, UpdatesToSCILatest)
{
    xpn.l_hpn = 0x11112222U;
    xpn.o_hpn = 0x33334444U;

    memset(sakuse.lmi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.delay_prot_ = true;
    sakuse.opn_ = 0x11223344U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));
    participant->current_sak.rxsa = &rxsa;

    // Expecting SCI reporting with extended packet number
    EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_UpdateNextPN(0U, participant->current_sak.rxsa, 0x3333444411223344ULL));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    // Internally storing extended packet number
    ASSERT_THAT(participant->current_sak.next_pn, Eq(0x3333444411223344ULL));
}

TEST_F(RxXPN, UpdatesToSCIOld)
{
    xpn.l_hpn = 0x11112222U;
    xpn.o_hpn = 0x33334444U;

    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.delay_prot_ = true;
    sakuse.lpn_ = 0x55443322U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memset(&participant->current_sak, 0, sizeof(participant->new_sak));
    participant->new_sak.rxsa = &rxsa;

    // Expecting SCI reporting with extended packet number
    EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_UpdateNextPN(0U, participant->new_sak.rxsa, 0x1111222255443322ULL));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    // Internally storing extended packet number
    ASSERT_THAT(participant->new_sak.next_pn, Eq(0x1111222255443322ULL));
}

TEST_F(RxXPN, NullLowestPacketNumberOld)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    xpn.l_hpn = 0x00000001U;
    sakuse.lpn_ = 0x00000000U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxXPN, NullLowestPacketNumberLatest)
{
    memset(sakuse.lmi_, 0, sizeof(sakuse.lmi_)); // Set invalid key in old slot so it doesnt interfere
    xpn.o_hpn = 0x00000001U;
    sakuse.opn_ = 0x00000000U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memset(&participant->current_sak, 0, sizeof(participant->new_sak));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxXPN, NullExtendedPacketNumberOld)
{
    memset(sakuse.lmi_, 0, sizeof(sakuse.lmi_)); // Set invalid key in old slot so it doesnt interfere
    xpn.o_hpn = 0x00000000U;
    sakuse.opn_ = 0x00000000U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memset(&participant->current_sak, 0, sizeof(participant->new_sak));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received SAK USE with 0 as Old Key Lowest Acceptable PN."), _));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxXPN, NullExtendedPacketNumberLatest)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    xpn.l_hpn = 0x00000000U;
    sakuse.lpn_ = 0x00000000U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received SAK USE with 0 as Latest Key Lowest Acceptable PN."), _));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxXPN, ExtendedExhaustion)
{
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_)); // Set invalid key in old slot so it doesnt interfere
    sakuse.lpn_ = 0xC0000000U;
    participant->sak_state = MKA_SAK_INSTALLED;
    memcpy(&participant->current_sak, &participant->new_sak, sizeof(participant->new_sak));
    memset(&participant->new_sak, 0, sizeof(participant->new_sak));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer reached PN exhaustion"), _)) .Times(0);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    xpn.l_hpn = 0xBFFFFFFFU;
    sakuse.lpn_ = 0xFFFFFFFFUL;

    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    xpn.l_hpn = 0xC0000000U;
    sakuse.lpn_ = 0x00000000ULL;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer reached PN exhaustion"), _)) .Times(1);

    // This action only happens in an attempt from kay to regenerate MI...
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(32, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(false)));

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, MetaTest)
{
}

TEST_F(RxDistSak, InvalidLength_27)
{
    distsak.invalid_sz_ = 27;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK with invalid length."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, InvalidLength_29)
{
    distsak.invalid_sz_ = 29;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK with invalid length."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, InvalidLength_35)
{
    distsak.invalid_sz_ = 35;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK with invalid length."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, PeerIsNotLive)
{
    lpeers.mi_[0] ^= 0xFF;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received peer list with different MI"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK from non-live peer."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, DiscardWhenKeyServer)
{
    bps.key_server_ = false;
    ctx->actor_priority = 0U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("DISTRIBUTED SAK but I am Key Server"), _)) .Times(1);

    // other layers
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(false)));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, PeerKeyServerDisablesMacsec_AcceptablePerConfiguration)
{
    bps.macsec_desired_ = false;
    distsak.empty_ = true;
    sakuse.present_ = false;
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_NULL;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer transmits DIST SAK with empty body. Silently ignored."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_AUTHENTICATED));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    EXPECT_THAT(participant->advertise_macsec_desired ,     Eq(false));
    EXPECT_THAT(participant->advertise_macsec_capability,   Eq(MKA_MACSEC_NOT_IMPLEMENTED));
    EXPECT_THAT(MKA_KAY_GetProtectFrames(0),                Eq(false));
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0),               Eq(MKA_VALIDATE_DISABLED));
}

TEST_F(RxDistSak, PeerKeyServerDisablesMacsec_NotAcceptablePerConfiguration)
{
    bps.macsec_desired_ = false;
    distsak.empty_ = true;
    sakuse.present_ = false;
    distsak.present_ = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot agree with peer on a MACsec cipher suite. Forgetting peer."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    ASSERT_THAT(peer->state, Eq(MKA_PEER_NONE));
    EXPECT_THAT(participant->advertise_macsec_capability,   Ne(MKA_MACSEC_NOT_IMPLEMENTED));
}

TEST_F(RxDistSak, PeerKeyServerEnablesMacsec_LocalNotSupported)
{
    bps.macsec_desired_ = true;
    ctx->macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
    sakuse.present_ = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot agree with peer on a MACsec cipher suite. Forgetting peer."), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
    EXPECT_THAT(participant->advertise_macsec_desired ,     Eq(false));
    EXPECT_THAT(participant->advertise_macsec_capability,   Eq(MKA_MACSEC_NOT_IMPLEMENTED));
}

TEST_F(RxDistSak, PeerKeyServerInstallingKnownKey)
{
    sakuse.lmn_ = 22U;
    distsak.keynum_ = 22U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Remote Key Server installing known SAK key"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, SakNonceProtection_TriggeredDueToPairSeen)
{
    // Let's inject an entry into the history list that matches new key
    memcpy(participant->ks_history[0].ki.mi, bps.mi_, sizeof(bps.mi_));
    participant->ks_history[0].ki.kn = 23U;
    participant->ks_history[0].next_pn = 1U; // TODO: Not sure about this... consequence of peer to peer?
    
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0U, MKA_PENDING)) .Times(AnyNumber());
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("SAK-nonce pair protection triggered!! SAK rejected"), _)) .Times(1);
    // after protection triggered peer became unknown to our MKA
    sakuse.present_ = true;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("SAK USE from non-live peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, SakNonceProtection_TriggeredDueToHistoryFull)
{
    // Let's inject an entry into the history list that matches new key
    for(int i=0; i<MKA_ARRAY_SIZE(participant->ks_history); ++i)
        participant->ks_history[i].next_pn = 569238U;
    
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0U, MKA_PENDING)) .Times(AnyNumber());
    EXPECT_CALL(mocks, MKA_GetRandomBytes(12, _)) .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mi, 12), Return(true)));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("No slot to record SAK-nonce pair. Restarting participant"), _)) .Times(1);
    // after protection triggered peer became unknown to our MKA
    sakuse.present_ = true;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("SAK USE from non-live peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, SakNonceNewEntry_WhileUsingNonAcceptableCipher)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);

    distsak.cipher_ = MKA_CS_ID_GCM_AES_128;
    for(int i=0; i<MKA_ARRAY_SIZE(test_buses_active_config.impl.cipher_preference); ++i)
        test_buses_active_config.impl.cipher_preference[i] = MKA_CS_ID_GCM_AES_256;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Key server is requesting a non-preferred cipher suite"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, SakNonceUpdate_WhileUsingNonKnownCipher)
{
    // Sak-nonce update
    memcpy(participant->ks_history[0].ki.mi, bps.mi_, sizeof(bps.mi_));
    participant->ks_history[0].ki.kn = 1U;
    participant->ks_history[0].next_pn = 1U;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Updating nonce-pair entry for received SAK"), _)) .Times(1);

    distsak.cipher_ = 22;
    for(int i=0; i<MKA_ARRAY_SIZE(test_buses_active_config.impl.cipher_preference); ++i)
        test_buses_active_config.impl.cipher_preference[i] = 22;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Key server is requesting unknown cipher suite"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, KeyUnwrap_AES128DefaultSmallHeader_NotAcceptable)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);

    for(int i=0; i<MKA_ARRAY_SIZE(test_buses_active_config.impl.cipher_preference); ++i)
        test_buses_active_config.impl.cipher_preference[i] = MKA_CS_ID_GCM_AES_256;

    distsak.header_ = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Key server is requesting default but non-preferred cipher suite. Discarded"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}


TEST_F(RxDistSak, KeyUnwrap_AES128DefaultSmallHeader)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);

    distsak.header_ = false;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK, unable to unwrap SAK key. Discarded."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_UnwrapKey(&participant->kek, MemoryWith<uint8_t>(distsak.wrap_, 24), 24, _)) .WillOnce(Return(false));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, KeyUnwrap_AES128_ExtendedHeader)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK, unable to unwrap SAK key. Discarded."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_UnwrapKey(&participant->kek, MemoryWith<uint8_t>(distsak.wrap_, 24), 24, _)) .WillOnce(Return(false));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, KeyUnwrap_AES256_ExtendedHeader)
{
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_256; // allow cipher
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);
    distsak.cipher_ = MKA_CS_ID_GCM_AES_256;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK, unable to unwrap SAK key. Discarded."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_UnwrapKey(&participant->kek, MemoryWith<uint8_t>(distsak.wrap_, 40), 40, _)) .WillOnce(Return(false));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, KeyInstallInSECY)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received DISTRIBUTED SAK but SECY is unable to install"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_UnwrapKey(&participant->kek, MemoryWith<uint8_t>(distsak.wrap_, 24), 24, _))
        .WillOnce(DoAll(
                SetArgPointee<3>(sak), //MemcpyToArg<3>((void*)&sak, sizeof(sak)),
                Return(true)
        ));
    t_MKA_ki identifier; memcpy(identifier.mi, bps.mi_, sizeof(bps.mi_)), identifier.kn = distsak.keynum_;
    EXPECT_CALL(mocks, MKA_SECY_InstallKey(
                /* bus      */ 0,
                /* key      */ ObjectMatch(sak),
                /* id       */ ObjectMatch(identifier),
                /* tx       */ true,
                /* rx       */ true
            )) .WillOnce(Return(nullptr));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(RxDistSak, NewSAKAdquiredAndInstalled_NoSakUseInPdu)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_UnwrapKey(&participant->kek, MemoryWith<uint8_t>(distsak.wrap_, 24), 24, _))
        .WillOnce(DoAll(
                SetArgPointee<3>(sak), //MemcpyToArg<3>((void*)&sak, sizeof(sak)),
                Return(true)
        ));
    t_MKA_ki identifier; memcpy(identifier.mi, bps.mi_, sizeof(bps.mi_)), identifier.kn = distsak.keynum_;
    EXPECT_CALL(mocks, MKA_SECY_InstallKey(
                /* bus      */ 0,
                /* key      */ ObjectMatch(sak),
                /* id       */ ObjectMatch(identifier),
                /* tx       */ true,
                /* rx       */ true
            )) .WillOnce(Return((void*)0x994212));
    
    EXPECT_CALL(mocks, MKA_CP_SetCipherSuite(0, MKA_CS_ID_GCM_AES_128));
    EXPECT_CALL(mocks, MKA_CP_SetCipherOffset(0, MKA_CONFIDENTIALITY_OFFSET_0));
    EXPECT_CALL(mocks, MKA_CP_SetDistributedKI(0, ObjectMatch(identifier)));
    EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, 2));
    EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    ASSERT_THAT(participant->new_sak.secy_reference,            Eq((void*)0x994212));
    ASSERT_THAT(participant->new_sak.next_pn,                   Eq(1));
    ASSERT_THAT(participant->new_sak.confidentiality_offset,    Eq(MKA_CONFIDENTIALITY_OFFSET_0));
    ASSERT_THAT(participant->new_sak.association_number,        Eq(2));
    ASSERT_THAT(participant->new_sak.cipher,                    Eq(MKA_CS_ID_GCM_AES_128));
    ASSERT_THAT(participant->new_sak.creation,                  Eq(mka_tick_time_ms));
    ASSERT_THAT(participant->new_sak.transmits,                 Eq(false));
    ASSERT_THAT(participant->new_sak.receives,                  Eq(false));
    ASSERT_THAT(participant->new_sak.identifier,                ObjectMatch(identifier));
    ASSERT_THAT(participant->new_sak.txsa,                      Eq(nullptr));
    ASSERT_THAT(participant->new_sak.rxsa,                      Eq(nullptr));
}

TEST_F(RxDistSak, NewSAKAdquiredAndInstalled_SakUse_EnabledAfterInstallation)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_UnwrapKey(&participant->kek, MemoryWith<uint8_t>(distsak.wrap_, 24), 24, _))
        .WillOnce(DoAll(
                SetArgPointee<3>(sak), //MemcpyToArg<3>((void*)&sak, sizeof(sak)),
                Return(true)
        ));
    t_MKA_ki identifier; memcpy(identifier.mi, bps.mi_, sizeof(bps.mi_)), identifier.kn = distsak.keynum_;
    EXPECT_CALL(mocks, MKA_SECY_InstallKey(
                /* bus      */ 0,
                /* key      */ ObjectMatch(sak),
                /* id       */ ObjectMatch(identifier),
                /* tx       */ true,
                /* rx       */ true
            )) .WillOnce(Return((void*)0x994212));
    
    EXPECT_CALL(mocks, MKA_CP_SetCipherSuite(0, MKA_CS_ID_GCM_AES_128));
    EXPECT_CALL(mocks, MKA_CP_SetCipherOffset(0, MKA_CONFIDENTIALITY_OFFSET_0));
    EXPECT_CALL(mocks, MKA_CP_SetDistributedKI(0, ObjectMatch(identifier)));
    EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, 2));
    EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0));

    // Let's say server were to say via "SAK USE" it's transmitting with this SAK already
    // in this case, client should notify CP to install SAK and enable it for tx/rx right away
    sakuse.present_ = true;
    sakuse.lan_ = 2;
    sakuse.lmn_ = distsak.keynum_;
    sakuse.lpn_ = 1;
    sakuse.ltx_ = true;
    sakuse.lrx_ = true;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Key Server is now transmitting with new SAK."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetServerTransmitting(0, true));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    ASSERT_THAT(participant->new_sak.secy_reference,            Eq((void*)0x994212));
    ASSERT_THAT(participant->new_sak.next_pn,                   Eq(1));
    ASSERT_THAT(participant->new_sak.confidentiality_offset,    Eq(MKA_CONFIDENTIALITY_OFFSET_0));
    ASSERT_THAT(participant->new_sak.association_number,        Eq(2));
    ASSERT_THAT(participant->new_sak.cipher,                    Eq(MKA_CS_ID_GCM_AES_128));
    ASSERT_THAT(participant->new_sak.creation,                  Eq(mka_tick_time_ms));
    ASSERT_THAT(participant->new_sak.transmits,                 Eq(false));
    ASSERT_THAT(participant->new_sak.receives,                  Eq(false));
    ASSERT_THAT(participant->new_sak.identifier,                ObjectMatch(identifier));
    ASSERT_THAT(participant->new_sak.txsa,                      Eq(nullptr));
    ASSERT_THAT(participant->new_sak.rxsa,                      Eq(nullptr));
}

TEST_F(CipherSuiteNegotiation, MetaTest)
{
}

TEST_F(CipherSuiteNegotiation, DefaultCipherWhenNoAnnouncementRecv_Confidentiality_0)
{
    ctx->macsec_capable = test_buses_active_config.kay.macsec_capable = MKA_MACSEC_INT_CONF_0_30_50;
    test_buses_active_config.impl.conf_offset_preference = MKA_CONFIDENTIALITY_OFFSET_30;
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_256;
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_128;

    ann.present_ = false;
    bps.macsec_desired_ = true;
    bps.macsec_cap_ = MKA_MACSEC_INT_CONF_0;

    // Expect confidentiality offset 0
    ExpectServerToAttemptSakTransmission(MKA_CS_ID_GCM_AES_128, MKA_CONFIDENTIALITY_OFFSET_0);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(CipherSuiteNegotiation, DefaultCipherWhenNoAnnouncementRecv_Integrity_1)
{
    ctx->macsec_capable = test_buses_active_config.kay.macsec_capable = MKA_MACSEC_INTEGRITY;
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_256;
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_128;

    ann.present_ = false;
    bps.macsec_desired_ = true;
    bps.macsec_cap_ = MKA_MACSEC_INT_CONF_0;

    // Expect integrity only
    ExpectServerToAttemptSakTransmission(MKA_CS_ID_GCM_AES_128, MKA_CONFIDENTIALITY_NONE);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(CipherSuiteNegotiation, DefaultCipherWhenNoAnnouncementRecv_Integrity_2)
{
    ctx->macsec_capable = test_buses_active_config.kay.macsec_capable = MKA_MACSEC_INT_CONF_0;
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_256;
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_128;

    ann.present_ = false;
    bps.macsec_desired_ = true;
    bps.macsec_cap_ = MKA_MACSEC_INTEGRITY;

    // Expect integrity only
    ExpectServerToAttemptSakTransmission(MKA_CS_ID_GCM_AES_128, MKA_CONFIDENTIALITY_NONE);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(CipherSuiteNegotiation, ServerSelectsPreferredCipherWhenSupported)
{
    ctx->macsec_capable = test_buses_active_config.kay.macsec_capable = MKA_MACSEC_INT_CONF_0;
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256; // supported by peer
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_XPN_128;
    test_buses_active_config.impl.cipher_preference[2] = MKA_CS_ID_GCM_AES_256;
    test_buses_active_config.impl.cipher_preference[3] = MKA_CS_ID_GCM_AES_128;

    ann.present_ = true;
    ann.resetCiphers();
    ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_256);
    ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_128);
    ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_XPN_256);
    
    bps.macsec_desired_ = true;
    bps.macsec_cap_ = MKA_MACSEC_INTEGRITY;

    // Expect server to choose its preferred ciphersuite even though it's not preferred by the peer
    ExpectServerToAttemptSakTransmission(MKA_CS_ID_GCM_AES_XPN_256, MKA_CONFIDENTIALITY_NONE);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}

TEST_F(CipherSuiteNegotiation, ServerSelectsSecondPreferredCipher)
{
    ctx->macsec_capable = test_buses_active_config.kay.macsec_capable = MKA_MACSEC_INT_CONF_0;
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256; // not supported by peer
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_XPN_128; // first that is supported
    test_buses_active_config.impl.cipher_preference[2] = MKA_CS_ID_GCM_AES_256;
    test_buses_active_config.impl.cipher_preference[3] = MKA_CS_ID_GCM_AES_128;

    ann.present_ = true;
    ann.resetCiphers();
    ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_256);
    ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_128);
    ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_XPN_128);
    
    bps.macsec_desired_ = true;
    bps.macsec_cap_ = MKA_MACSEC_INTEGRITY;

    // Expect server to choose its preferred ciphersuite even though it's not preferred by the peer
    ExpectServerToAttemptSakTransmission(MKA_CS_ID_GCM_AES_XPN_128, MKA_CONFIDENTIALITY_NONE);

    FeedFrame(/*serialise*/true, /*handle_icv*/true);
}
