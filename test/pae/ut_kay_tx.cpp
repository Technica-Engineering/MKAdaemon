/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: ut_kay_tx.cpp
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
extern "C" {
 #include "mka_kay_internal.h"
 #include "mocks.h"
 #include "kay_helpers.h"
}



struct TxBasic : public KayTestBase {
    ILayer*     composition[16U] = { &ethhdr, &eapol, &bps, &lpeers, &ppeers, &sakuse, &distsak, &ann, &xpn, &icv };
    virtual ILayer** getLayout(void) { return composition; }

    uint8_t sak_wrapped[40U];
    uint8_t cp_dist_an;
    t_MKA_ki cp_dist_ki = {{0U}};

    TxBasic(void) { }

    void SetUp(void)
    {
        for(int i=0; i<40; ++i)
            sak_wrapped[i] = (15*i*i*i+4*i*i+11*i+31) % 255;

        KayTestBase::SetUp(false);

        // Unhandled SA --> No SA used
        EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, _, _, _, _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, _, _, _, _)) .Times(AnyNumber());

        //EXPECT_CALL(mocks, MKA_l2_init(0, MKA_L2_PROTO_EAPOL)) .Times(1);
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received EAPOL message from"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Creating new participant MI"), _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cleaning up peer"), _)) .Times(AnyNumber());

        // Ignored, no SAK shall be installed at this point
        EXPECT_CALL(mocks, MKA_l2_init(0, 0x888E));
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
        participant->mn = 1U;

        xpn.present_ = false;
    }

    void learnPeerAsKeyServer(bool layers_reset=true, bool handle_sak_wrapped=true, bool secure_channel=true, bool sak_learn=false,
                            t_MKA_connect_mode target_mode=MKA_SECURED)
    {
        if (sak_learn) {
            HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);
        }
        if (layers_reset) {
            layersReset();
        }
        {
            ann.present_ = true;
            ann.resetCiphers();
            ann.addCipher(MKA_MACSEC_INT_CONF_0, test_buses_active_config.impl.cipher_preference[0]);
        }
        ctx->role = MKA_ROLE_FORCE_KEY_SERVER; // Configure kay as key client
        bps.key_server_ = true; // Announce peer as server
        SetPresentLayers(M_PPEERS + (ann.present_ ? M_ANN : M_NONE));

        // Go straight to learn live peer
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self as key server."), _)) .Times(1);
        EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
        EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
        EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, target_mode));

        // Prepare mocks to generate SAK
        EXPECT_CALL(mocks, MKA_CP_SetCipherSuite(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetCipherOffset(0, _));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedKI(0, _)) .WillOnce(SaveArgPointee<1>(&cp_dist_ki));
        EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, _)) .WillOnce(SaveArg<1>(&cp_dist_an));
        EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0)) .WillOnce(
            Invoke([this, secure_channel](t_MKA_bus bus) { // lambdas as actions capturing this object, marvellous!!
                if (secure_channel) {
                    MKA_KAY_CreateSAs(bus, &this->cp_dist_ki);
                    MKA_KAY_EnableReceiveSAs(bus, &this->cp_dist_ki);
                }
            }));
        if (secure_channel) {
            //EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSC(0, ObjectMatch(ctx->actor_sci))) .WillOnce(Return(&txsc));
            EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSC(0, ObjectMatch(peer->sci))) .WillOnce(Return(&rxsc));
            EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSA(0, 1, 1, _, _, _)) .WillOnce(Return(&txsa));
            EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSA(0, 1, 1, _, _)) .WillOnce(Return(&rxsa));
            EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_EnableReceive(0, &rxsa));
            EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, true));
        }
        if (handle_sak_wrapped) {
            EXPECT_CALL(mocks, MKA_DeriveSAK(_, _, _, _, 1, _, _)) .WillOnce(DoAll(MemcpyToArg<6>((void*)&sak, sizeof(sak)), Return(true)));
            EXPECT_CALL(mocks, MKA_GetRandomBytes(AnyOf(Eq(32), Eq(16)), _))
                    .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(true)));
            EXPECT_CALL(mocks, MKA_SECY_InstallKey(0, _, _, true, true)) .WillOnce(Return((void*)12345));
            EXPECT_CALL(mocks, MKA_WrapKey(_, _, _)) .WillOnce(DoAll(
                    MemcpyToArg<2>(sak_wrapped, 40U),
                    Return(true))
            );
        }
        if (MKA_SECURED == target_mode) {
            EXPECT_CALL(mocks, MKA_CP_GetProtectFrames(0)) .WillOnce(Return(true));
            EXPECT_CALL(mocks, MKA_CP_GetValidateFrames(0)) .WillOnce(Return(MKA_VALIDATE_STRICT));
        }
        if (sak_learn) {
            // Default key usage
            EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
                SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
            EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
                SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(cp_dist_an), SetArgPointee<3>(false), SetArgPointee<4>(true)));
        }
        FeedFrame(/*serialise*/true, /*handle_icv*/true);

        if (sak_learn) {
            bool const is_xpn = (MKA_CS_ID_GCM_AES_XPN_256 == participant->cipher) || (MKA_CS_ID_GCM_AES_XPN_128 == participant->cipher);
            bool const rcv_ann = test_buses_active_config.port_capabilities.announcements;

            ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + (rcv_ann ? M_ANN : M_NONE) + M_XPN); //(is_xpn ? M_XPN : 0U));

            layersReset();
            if (MKA_CS_ID_GCM_AES_128 != test_buses_active_config.impl.cipher_preference[0]) {
                ann.present_ = true;
                ann.resetCiphers();
                ann.addCipher(MKA_MACSEC_INT_CONF_0, test_buses_active_config.impl.cipher_preference[0]);
            }
            SetPresentLayers(M_LPEERS + M_SAKUSE + (ann.present_ ? M_ANN : M_NONE) + (is_xpn ? M_XPN : 0U));
            sakuse.lrx_ = true;
            memset(sakuse.omi_, 0, sizeof(sakuse.omi_));
            EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer is now receiving with distributed SAK."), _)) .Times(1);

            EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .WillRepeatedly(DoAll(
                SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(cp_dist_an), SetArgPointee<3>(true), SetArgPointee<4>(true)));
            EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .WillRepeatedly(DoAll(
                SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
            EXPECT_CALL(mocks, MKA_CP_SetAllReceiving(0, true)) .WillOnce(
                Invoke([this](t_MKA_bus bus, bool en) {
                    static t_MKA_ki current_ki = {{0}, sakuse.lmn_};
                    memcpy(current_ki.mi, sakuse.lmi_, sizeof(current_ki.mi));
                    MKA_KAY_EnableTransmitSA(0, &current_ki);
                    MKA_KAY_DeleteSAs(0, &null_ki);
                }));
            EXPECT_CALL(mocks, MKA_SECY_TransmitSA_EnableTransmit(0, _));
            EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, true));
            FeedFrame(/*serialise*/true, /*handle_icv*/true);
        }
    }
};

struct TxTimers : public TxBasic {};

struct TxPeerList : public TxBasic {};
struct TxDistSak : public TxBasic {
    virtual void SetUp(void) {
        TxBasic::SetUp();
        layersReset();
    }
};
struct TxWhenServer : public TxBasic { };
struct TxWhenClient : public TxBasic { };

struct TxAnnouncement : public TxBasic {
    virtual void SetUp(void) {
        TxBasic::SetUp();
        test_buses_active_config.port_capabilities.announcements = true;
        //participant->advertise_macsec_capability = MKA_MACSEC_INT_CONF_0_30_50;
        ctx->macsec_capable = MKA_MACSEC_INT_CONF_0_30_50;
        for(int i=0; i<MKA_ARRAY_SIZE(test_buses_active_config.impl.cipher_preference); ++i) {
            test_buses_active_config.impl.cipher_preference[i] = MKA_CS_INVALID;
        }
    }
};

struct TxXPN : public TxBasic {
    virtual void SetUp(void) {
        test_buses_active_config.port_capabilities.announcements = true;
        test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256;
        test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_XPN_128;
        TxBasic::SetUp();
        layersReset();
        xpn.present_ = true;
        ann.present_ = true;
        ann.resetCiphers();
        ann.addCipher(MKA_MACSEC_INT_CONF_0, MKA_CS_ID_GCM_AES_XPN_256);
    }
};


TEST_F(TxBasic, MetaTest)
{
}

TEST_F(TxBasic, NoTransmissionWithoutParticipate)
{
    MKA_KAY_Participate(0, false);

    EXPECT_CALL(mocks, MKA_l2_receive(0, _, _)) .WillRepeatedly(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_l2_transmit(_, _, _)) .Times(0);
    for(int timecnt = 0; timecnt < 10000; timecnt += 1000)
    {
        mka_tick_time_ms += 1000U;
        MKA_KAY_MainFunction(0);
    }
}

TEST_F(TxBasic, NoActivityWhenDisabled)
{
    EXPECT_CALL(mocks, MKA_LOGON_SetKayEnabled(0, false));
    EXPECT_CALL(mocks, MKA_LOGON_SignalDeletedMKA(0));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("KAY disabled for this bus."), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cleaning up participant."), _)) .Times(1);

    MKA_KAY_SetEnable(0, false);
    MKA_KAY_MainFunctionTimers(0U);

    EXPECT_CALL(mocks, MKA_l2_receive(0, _, _)) .WillRepeatedly(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_l2_transmit(_, _, _)) .Times(0);

    for(int timecnt = 0; timecnt < 10000; timecnt += 1000)
    {
        mka_tick_time_ms += 1000U;
        MKA_KAY_MainFunction(0);
    }
}

TEST_F(TxBasic, SignalNewInfoCausesTransmission)
{
    MKA_KAY_Participate(0, false);
    MKA_KAY_SignalNewInfo(0);

    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  _,
            /* length   */  _,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(icv.icv_, MKA_ICV_LENGTH),
                Return(true)
        )) .RetiresOnSaturation();
    EXPECT_CALL(mocks, MKA_l2_transmit(_, _, _)) .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_l2_receive(0, _, _)) .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Layer 2 module rejecting transmission"), _)) .Times(1);
    MKA_KAY_MainFunction(0);
}

TEST_F(TxBasic, TransmissionWhenParticipate)
{
    MKA_KAY_Participate(0, true);
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  _,
            /* length   */  _,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(icv.icv_, MKA_ICV_LENGTH),
                Return(true)
        )) .RetiresOnSaturation();
    EXPECT_CALL(mocks, MKA_l2_transmit(_, _, _)) .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_l2_receive(0, _, _)) .WillOnce(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Layer 2 module rejecting transmission"), _)) .Times(1);
    MKA_KAY_MainFunction(0);
}

TEST_F(TxBasic, FailsAfterMkaLifeTimeWithoutPeers)
{
    MKA_KAY_Participate(0, true);

    EXPECT_CALL(mocks, MKA_l2_transmit(_, _, _)) .WillRepeatedly(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, MKA_l2_receive(0, _, _)) .WillRepeatedly(Return(MKA_NOT_OK));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Layer 2 module rejecting transmission"), _)) .Times(AnyNumber());
    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  _,
            /* length   */  _,
            /* ICV      */  _
        )) .WillRepeatedly(DoAll(
                MemcpyToArg<4>(icv.icv_, MKA_ICV_LENGTH),
                Return(true)
        )) .RetiresOnSaturation();

    mka_tick_time_ms += 1000U;
    MKA_KAY_MainFunction(0);        // 1 seg
    mka_tick_time_ms += 1000U;
    MKA_KAY_MainFunction(0);        // 2 seg
    mka_tick_time_ms += 3999U;
    MKA_KAY_MainFunction(0);        // 5.999 seg
    mka_tick_time_ms += 1U;
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_FAILED));
    MKA_KAY_MainFunction(0);        // 6.000 seg
}

TEST_F(TxBasic, EthernetHeaderValidation)
{
    HandleTransmission();
    ASSERT_THAT(frame_size, Ge(14));
    ASSERT_THAT(ethhdr.src_.addr, MemoryWith<uint8_t>(local_mac, 6U));
    ASSERT_THAT(ethhdr.dst_.addr, MemoryWith<uint8_t>({ 0x01U, 0x80U, 0xC2U, 0x00U, 0x00U, 0x03U }));
    ASSERT_THAT(ethhdr.type_, Eq(0x888EU));
}

TEST_F(TxBasic, EAPOLheaderValidation)
{
    HandleTransmission();
    ASSERT_THAT(frame_size, Ge(14+4));
    ASSERT_THAT(eapol.version_, Eq(3));
    ASSERT_THAT(eapol.body_len_, Eq(frame_size - 14 - 4));
}

TEST_F(TxBasic, BasicParameterSetValidation)
{
    HandleTransmission();
    ASSERT_THAT(ppeers.present_, false);
    ASSERT_THAT(lpeers.present_, false);
    ASSERT_THAT(sakuse.present_, false);
    ASSERT_THAT(distsak.present_, false);
    ASSERT_THAT(frame_size, Ge(14+4+30));
    ASSERT_THAT(bps.present_, Eq(1U));
    ASSERT_THAT(bps.version_, Eq(3U));
    ASSERT_THAT(bps.priority_, Eq(128U));
    ASSERT_THAT(bps.key_server_, Eq(true));
    ASSERT_THAT(bps.macsec_desired_, Eq(true));
    ASSERT_THAT(bps.macsec_cap_, Eq(ctx->macsec_capable));
    ASSERT_THAT(bps.sci_.addr, ObjectMatch(ethhdr.src_.addr));
    ASSERT_THAT(bps.sci_.port, Eq(1U));
    ASSERT_THAT(bps.mi_, ObjectMatch(local_mi));
    ASSERT_THAT(bps.algo_, Eq(MKA_ALGORITHM_AGILITY));
    ASSERT_THAT(bps.ckn_, MemoryWith<char>({'a', 'b'}));

    ctx->role = MKA_ROLE_FORCE_KEY_CLIENT;
    ctx->macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;

    HandleTransmission();
    ASSERT_THAT(bps.priority_, Eq(0xFFU));
    ASSERT_THAT(bps.key_server_, Eq(false));
    ASSERT_THAT(bps.macsec_desired_, Eq(false));
    ASSERT_THAT(bps.macsec_cap_, Eq(MKA_MACSEC_NOT_IMPLEMENTED));

    ctx->actor_priority = 45U;
}

TEST_F(TxBasic, MnIncreasesAndICVupdates)
{
    HandleTransmission();   // Let DUT generate one first frame
    uint8_t dummy_icv[16];
    for(int i=0; i<16; ++i)
        dummy_icv[i] = (17*i*i*i+7*i*i+11*i+87) % 255;

    // Modify MN to expect the next one, this corresponds to byte 45 (see pcap of test with wireshark)
    ++frame[45];

    EXPECT_CALL(mocks, MKA_ComputeICV(
            /* alg. ag  */  MKA_ALGORITHM_AGILITY,
            /* ICK      */  &mka_kay[0].participant.ick,
            /* message  */  MemoryWith<uint8_t>(frame, frame_size-16),
            /* length   */  frame_size-16,
            /* ICV      */  _
        )) .WillOnce(DoAll(
                MemcpyToArg<4>(dummy_icv, MKA_ICV_LENGTH),
                Return(true)
        )) .RetiresOnSaturation();

    HandleTransmission(true, false);

    EXPECT_THAT(&frame[frame_size-16], MemoryWith<uint8_t>(dummy_icv, 16));
}

TEST_F(TxBasic, AnnounceKeyServerAsConfigured)
{
    ctx->role = MKA_ROLE_FORCE_KEY_CLIENT;
    HandleTransmission();
    ASSERT_THAT(bps.key_server_, Eq(false));

    ctx->role = MKA_ROLE_FORCE_KEY_SERVER;
    HandleTransmission();
    ASSERT_THAT(bps.key_server_, Eq(true));

    ctx->role = MKA_ROLE_AUTO;
    HandleTransmission();
    ASSERT_THAT(bps.key_server_, Eq(true));
}

TEST_F(TxTimers, MetaTest)
{
}

TEST_F(TxTimers, HelloRampup_ImmediateTransmitAfterParticipate)
{
    MKA_KAY_Participate(0, true);
    HandleTransmission(false);
}
TEST_F(TxTimers, HelloRampup_CycleWhenNoPeers)
{
    MKA_KAY_Participate(0, true);
    HandleTransmission(false);
    ExpectNoTransmission(); // No transmission in the same tick

    ::testing::Mock::VerifyAndClearExpectations(&mocks);

    // No keys in use
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, _, _, _, _)) .Times(AnyNumber());
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, _, _, _, _)) .Times(AnyNumber());

    // UT config: 100, 200, 400, 800, 800
    //  - t0
    //  - t0+100
    //  - t0+100+200=t0+300
    //  - t0+300+400=t0+700
    //  - t0+700+800=t0+1500
    //  - t0+1500+800=t0+2300

    uint32_t t0 = mka_tick_time_ms;
    for(uint32_t t = 0; t < 2301; t += 50) {
        mka_tick_time_ms = t0 + t;
        if (    (100 == t) || (300 == t) || (700 == t) ||
                (1500 == t) || (2300 == t)              ) {
            HandleTransmission(false);
        }
        else {
            ExpectNoTransmission();
        }
        ASSERT_TRUE(::testing::Mock::VerifyAndClearExpectations(&mocks))
                << "cycle failure happened at time t0+" << t;

        // No keys in use
        EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, _, _, _, _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, _, _, _, _)) .Times(AnyNumber());
    }

    // Afterwards, regular messages with period MKA_active_global_config->hello_time
    // - t0+2300
    // - t0+3100
    // - t0+3900
    // - t0+4700
    // - t0+5500
    t0 = mka_tick_time_ms;
    for(uint32_t t = 100; t < (10*MKA_active_global_config->hello_time); t += 100) {
        mka_tick_time_ms = t0 + t;

        // Pending -> Failed in LOGON mode, after life time elapsed!
        if (MKA_active_global_config->life_time == (t + 2300)) {
            EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_FAILED));
        }
        else {
            EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(_,_)) .Times(0);
        }

        // Transmission / no transmission
        if (0 == (t % MKA_active_global_config->hello_time)) {
            HandleTransmission(false);
        }
        else {
            ExpectNoTransmission();
        }
        ASSERT_TRUE(::testing::Mock::VerifyAndClearExpectations(&mocks))
                << "cycle failure happened at time t0'+" << t << " == t0+" << (2300+t);

        // No keys in use
        EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, _, _, _, _)) .Times(AnyNumber());
        EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, _, _, _, _)) .Times(AnyNumber());
    }
}

TEST_F(TxPeerList, MetaTest)
{
}

TEST_F(TxPeerList, PotentialPeerIsTransmitted)
{
    HandleTransmission();
    layersReset();
    SetPresentLayers(M_NONE);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    HandleTransmission();
    ExpectPresentLayers(M_PPEERS);

    ASSERT_THAT(ppeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
    ASSERT_THAT(ppeers.mn_, Eq(0x10AU));
}

TEST_F(TxPeerList, PotentialPeerExpires)
{
    HandleTransmission();
    layersReset();
    SetPresentLayers(M_NONE);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    for(int i=0; i<6; ++i) {
        HandleTransmission();
        ExpectPresentLayers(M_PPEERS);

        ASSERT_THAT(ppeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
        ASSERT_THAT(ppeers.mn_, Eq(0x10AU));

        mka_tick_time_ms += 1000U;
    }

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Potential peer timed out"), _)) .Times(1);
    HandleTransmission();
    ExpectPresentLayers(M_NONE);
}

TEST_F(TxPeerList, PotentialPeerTransitionsToLive)
{
    HandleTransmission();
    layersReset();
    SetPresentLayers(M_NONE);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    SetPresentLayers(M_PPEERS);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
    { // As key server, attempts to create SAK
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
        EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(Return(false));
    }
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    // Retries to create SAK
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(Return(false));
    HandleTransmission();
    ExpectPresentLayers(M_LPEERS); // server cannot distribute sak yet, not created

    ASSERT_THAT(lpeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
    ASSERT_THAT(lpeers.mn_, Eq(0x10BU));
}

TEST_F(TxPeerList, NewPeerTransitionsToLive)
{
    HandleTransmission();
    layersReset();
    SetPresentLayers(M_PPEERS);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
    { // As key server, attempts to create SAK
        EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
        EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(Return(false));
    }
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    // Retries to create SAK
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot create ks_nonce"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _)) .WillOnce(Return(false));
    HandleTransmission();
    ExpectPresentLayers(M_LPEERS); // server cannot distribute sak yet, not created

    ASSERT_THAT(lpeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
    ASSERT_THAT(lpeers.mn_, Eq(0x10AU));
}

TEST_F(TxPeerList, SecondaryPeerLearntAsPotential)
{
    ctx->role = MKA_ROLE_FORCE_KEY_CLIENT; // Configure kay as key client, easier to test and not relevant
    HandleTransmission();
    layersReset();
    SetPresentLayers(M_PPEERS);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected principal actor"), _)) .Times(AnyNumber());
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected peer as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, false));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    rx_mn = 1U;
    bps.mi_[11] = 5U;
    SetPresentLayers(M_NONE);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received MKPDU from peer with same SCI, different MI. Learning as secondary until live"), _));
    // transmission expected due to new potential peer
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    HandleTransmission();
    ExpectPresentLayers(M_LPEERS + M_PPEERS);

    ASSERT_THAT(ppeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 5}));
    ASSERT_THAT(ppeers.mn_, Eq(1U));
    ASSERT_THAT(lpeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
    ASSERT_THAT(lpeers.mn_, Eq(0x10AU));
}

TEST_F(TxPeerList, SecondaryPeerTimeout)
{
    ctx->role = MKA_ROLE_FORCE_KEY_CLIENT; // Configure kay as key client, easier to test and not relevant
    HandleTransmission();
    layersReset();
    SetPresentLayers(M_PPEERS);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected principal actor"), _)) .Times(AnyNumber());
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected peer as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, false));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    uint32_t const old_mn = rx_mn;
    rx_mn = 1U;
    bps.mi_[11] ^= 5U;
    SetPresentLayers(M_NONE);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received MKPDU from peer with same SCI, different MI. Learning as secondary until live"), _));
    // transmission expected due to new potential peer
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    //HandleTransmission();
    ExpectPresentLayers(M_LPEERS + M_PPEERS);

    ASSERT_THAT(ppeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 4}));
    ASSERT_THAT(ppeers.mn_, Eq(1U));
    ASSERT_THAT(lpeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
    ASSERT_THAT(lpeers.mn_, Eq(0x10AU));

    mka_tick_time_ms += 3000U;

    // refresh primary
    rx_mn = old_mn;
    layersReset();
    /* bps.mi_[11] ^= 5U; */
    bps.key_server_ = true;
    lpeers.mn_ = 2U;
    SetPresentLayers(M_LPEERS);
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    mka_tick_time_ms += 3000U;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Secondary peer timed out"), _));
    HandleTransmission();
    ExpectPresentLayers(M_LPEERS);
    ASSERT_THAT(lpeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}));
    ASSERT_THAT(lpeers.mn_, Eq(0x10BU));
}

TEST_F(TxPeerList, SecondaryPeerReplacesPrimary)
{
    ctx->role = MKA_ROLE_FORCE_KEY_CLIENT; // Configure kay as key client, easier to test and not relevant
    HandleTransmission();
    layersReset();
    SetPresentLayers(M_PPEERS);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected principal actor"), _)) .Times(AnyNumber());
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected peer as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, false));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    rx_mn = 1U;
    bps.mi_[11] = 5U;
    SetPresentLayers(M_PPEERS);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Received MKPDU from peer with same SCI, different MI. Learning as secondary until live"), _));
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Secondary peer is live. Replacing primary"), _));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_PENDING));
    EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, true));
    EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, true));

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected principal actor"), _)) .Times(AnyNumber());
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected peer as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, false));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Live peer did not sent peer live list. Presence timers not updated."), _));

    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    HandleTransmission();
    ExpectPresentLayers(M_LPEERS);

    ASSERT_THAT(lpeers.mi_, MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 5}));
    ASSERT_THAT(lpeers.mn_, Eq(1U));
}


TEST_F(TxDistSak, MetaTest)
{
}

TEST_F(TxDistSak, DistSakAndSakUseEmptyWithoutMacsec)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKA_EVENT_LINKUP"), _)) .Times(1);

    ctx->macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    layersReset();
    bps.macsec_desired_ = false;
    bps.macsec_cap_ = MKA_MACSEC_NOT_IMPLEMENTED;

    learnPeerAsKeyServer(/* layer rst */false, /*sak_wrapped*/false, /*secure_channel*/false,
                        /*sak_learn*/false, /*target_mode*/MKA_AUTHENTICATED);

    // I'm considering 4 results :
    // No DISTSAK, no SAKUSE -> valid
    // empty DISTSAK, no SAKUSE -> valid
    // no DISTSAK, empty SAKUSE -> valid
    // empty DISTSAK, empty SAKUSE -> valid
    EXPECT_FALSE(ppeers.present_);
    EXPECT_TRUE(lpeers.present_);

    EXPECT_TRUE(sakuse.present_ && sakuse.empty_) << "present: " << sakuse.present_ << " empty: " << sakuse.empty_;
    EXPECT_TRUE(distsak.present_ && distsak.empty_) << "present: " << distsak.present_ << " empty: " << distsak.empty_;

    EXPECT_THAT(MKA_KAY_GetProtectFrames(0),                Eq(false));
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0),               Eq(MKA_VALIDATE_DISABLED));
}

TEST_F(TxDistSak, DistSakOptionallyNotTransmittedWithoutMacsec)
{
    test_global_active_config.transmit_empty_dist_sak = false;
    test_global_active_config.transmit_empty_sak_use = true;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKA_EVENT_LINKUP"), _)) .Times(1);

    ctx->macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    layersReset();
    bps.macsec_desired_ = false;
    bps.macsec_cap_ = MKA_MACSEC_NOT_IMPLEMENTED;

    learnPeerAsKeyServer(/* layer rst */false, /*sak_wrapped*/false, /*secure_channel*/false,
                        /*sak_learn*/false, /*target_mode*/MKA_AUTHENTICATED);

    // I'm considering 4 results :
    // No DISTSAK, no SAKUSE -> valid
    // empty DISTSAK, no SAKUSE -> valid
    // no DISTSAK, empty SAKUSE -> valid
    // empty DISTSAK, empty SAKUSE -> valid
    EXPECT_FALSE(ppeers.present_);
    EXPECT_TRUE(lpeers.present_);

    EXPECT_TRUE(sakuse.present_ && sakuse.empty_) << "present: " << sakuse.present_ << " empty: " << sakuse.empty_;
    EXPECT_TRUE(!distsak.present_) << "present: " << distsak.present_ << " empty: " << distsak.empty_;
}

TEST_F(TxDistSak, SakUseOptionallyNotTransmittedWithoutMacsec)
{
    test_global_active_config.transmit_empty_dist_sak = true;
    test_global_active_config.transmit_empty_sak_use = false;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKA_EVENT_LINKUP"), _)) .Times(1);

    ctx->macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    layersReset();
    bps.macsec_desired_ = false;
    bps.macsec_cap_ = MKA_MACSEC_NOT_IMPLEMENTED;

    learnPeerAsKeyServer(/* layer rst */false, /*sak_wrapped*/false, /*secure_channel*/false,
                        /*sak_learn*/false, /*target_mode*/MKA_AUTHENTICATED);

    // I'm considering 4 results :
    // No DISTSAK, no SAKUSE -> valid
    // empty DISTSAK, no SAKUSE -> valid
    // no DISTSAK, empty SAKUSE -> valid
    // empty DISTSAK, empty SAKUSE -> valid
    EXPECT_FALSE(ppeers.present_);
    EXPECT_TRUE(lpeers.present_);

    EXPECT_TRUE(!sakuse.present_) << "present: " << sakuse.present_ << " empty: " << sakuse.empty_;
    EXPECT_TRUE(distsak.present_ && distsak.empty_) << "present: " << distsak.present_ << " empty: " << distsak.empty_;
}

TEST_F(TxDistSak, DerivationError)
{
    participant->cipher = MKA_CS_ID_GCM_AES_128;

    t_MKA_ki ki;
    memcpy(ki.mi, participant->mi, sizeof(ki.mi));
    ki.kn = 1U;

    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _))
            .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 16), Return(true)));

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot derive SAK key from CAK"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_DeriveSAK(
            /* cak          */ ObjectMatch(cak),
            /* ks_nonce     */ MemoryWith<uint8_t>(ks_nonce, 16U),
            /* mi           */ ObjectMatch(participant->mi),
            /* peer mi      */ ObjectMatch(bps.mi_),
            /* kn           */ 1U,
            /* out_len      */ 16U,
            /* sak          */ _
        )) .WillOnce(Return(false));

    layersReset();
    ctx->role = MKA_ROLE_FORCE_KEY_SERVER; // Configure kay as key server
    bps.key_server_ = false; // Announce peer as client
    SetPresentLayers(M_PPEERS);

    // Go straight to learn live peer
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected self as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, true));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));

    // Transmission will not happen
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    // Retries next tick.

    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _))
            .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 16), Return(true)));

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Cannot derive SAK key from CAK"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_DeriveSAK(
            /* cak          */ ObjectMatch(cak),
            /* ks_nonce     */ MemoryWith<uint8_t>(ks_nonce, 16U),
            /* mi           */ ObjectMatch(participant->mi),
            /* peer mi      */ ObjectMatch(bps.mi_),
            /* kn           */ 1U,
            /* out_len      */ 16U,
            /* sak          */ _
        )) .WillOnce(Return(false));

    // Transmission will not happen

    EXPECT_CALL(mocks, MKA_l2_receive(0, _, _)) .WillOnce(Return(MKA_NOT_OK));
    MKA_KAY_MainFunction(0);
}

TEST_F(TxDistSak, Key128bitsWrapped)
{
    participant->cipher = MKA_CS_ID_GCM_AES_128;
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    t_MKA_ki ki;
    memcpy(ki.mi, participant->mi, sizeof(ki.mi));
    ki.kn = 1U;

    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _))
            .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 16), Return(true)));
    EXPECT_CALL(mocks, MKA_DeriveSAK(
            /* cak          */ ObjectMatch(cak),
            /* ks_nonce     */ MemoryWith<uint8_t>(ks_nonce, 16U),
            /* mi           */ ObjectMatch(participant->mi),
            /* peer mi      */ ObjectMatch(bps.mi_),
            /* kn           */ 1U,
            /* out_len      */ 16U,
            /* sak          */ _
        )) .WillOnce(DoAll(
                MemcpyToArg<6>((void*)&sak, sizeof(sak)),
                Return(true)
        ));
    EXPECT_CALL(mocks, MKA_SECY_InstallKey(
            /* bus          */ 0,
            /* sak          */ ObjectMatch(sak),
            /* id           */ ObjectMatch(ki),
            /* tx/rx        */ true, true
        )) .WillOnce(Return((void*)12345));

    EXPECT_CALL(mocks, MKA_WrapKey(
            /* kek          */ ObjectMatch(kek),
            /* sak          */ ObjectMatch(sak),
            /* out wrapped  */ _)
            ) .WillOnce(DoAll(
                    MemcpyToArg<2>(sak_wrapped, 24U),
                    Return(true))
            );

    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&ki), SetArgPointee<2>(1), SetArgPointee<3>(false), SetArgPointee<4>(true)));

    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/false);

    EXPECT_THAT(MKA_KAY_GetValidateFrames(0), Eq(MKA_VALIDATE_STRICT));
    EXPECT_THAT(MKA_KAY_GetProtectFrames(0), Eq(true));

    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.lan_,        Eq(1));
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(true));
    EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.lmn_,        1U);
    EXPECT_THAT(sakuse.lpn_,        txsa.next_pn);

    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(false));
    // IRELEVANT: not in use
    //EXPECT_THAT(sakuse.oan_,        Eq(0));
    //EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>({0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
    //EXPECT_THAT(sakuse.omn_,        0U);
    //EXPECT_THAT(sakuse.opn_,        0U);

    EXPECT_THAT(distsak.empty_,     Eq(false));
    EXPECT_THAT(distsak.header_,    Eq(false)); // 128 is the default key, reduced dist-sak expected!
    EXPECT_THAT(distsak.dan_,       Eq(cp_dist_an));
    EXPECT_THAT(distsak.conf_off_,  Eq(1U));
    EXPECT_THAT(distsak.keynum_,    Eq(1U));
    EXPECT_THAT(distsak.wrap_,      MemoryWith<uint8_t>(sak_wrapped, 24U));

    EXPECT_THAT(MKA_KAY_GetProtectFrames(0),                Eq(true));
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0),               Eq(MKA_VALIDATE_STRICT));
}

TEST_F(TxDistSak, Key256bitsWrappedExtendedHeader)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_256;
    //participant->cipher = MKA_CS_ID_GCM_AES_256;
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    t_MKA_ki ki;
    memcpy(ki.mi, participant->mi, sizeof(ki.mi));
    ki.kn = 1U;

    EXPECT_CALL(mocks, MKA_GetRandomBytes(32, _))
            .WillOnce(DoAll(MemcpyToArg<1>((void*)ks_nonce, 32), Return(true)));
    EXPECT_CALL(mocks, MKA_DeriveSAK(
            /* cak          */ ObjectMatch(cak),
            /* ks_nonce     */ MemoryWith<uint8_t>(ks_nonce, 32U),
            /* mi           */ ObjectMatch(participant->mi),
            /* peer mi      */ ObjectMatch(bps.mi_),
            /* kn           */ 1U,
            /* out_len      */ 32U,
            /* sak          */ _
        )) .WillOnce(DoAll(
                MemcpyToArg<6>((void*)&sak, sizeof(sak)),
                Return(true)
        ));
    EXPECT_CALL(mocks, MKA_SECY_InstallKey(
            /* bus          */ 0,
            /* sak          */ ObjectMatch(sak),
            /* id           */ ObjectMatch(ki),
            /* tx/rx        */ true, true
        )) .WillOnce(Return((void*)12345));

    EXPECT_CALL(mocks, MKA_WrapKey(
            /* kek          */ ObjectMatch(kek),
            /* sak          */ ObjectMatch(sak),
            /* out wrapped  */ _)
            ) .WillOnce(DoAll(
                    MemcpyToArg<2>(sak_wrapped, 40U),
                    Return(true))
            );

    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&ki), SetArgPointee<2>(1), SetArgPointee<3>(false), SetArgPointee<4>(true)));

    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/false);

    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.lan_,        Eq(1));
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(true));
    EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.lmn_,        1U);
    EXPECT_THAT(sakuse.lpn_,        txsa.next_pn);

    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(false));
    // IRELEVANT: not in use
    //EXPECT_THAT(sakuse.oan_,        Eq(0));
    //EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>({0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
    //EXPECT_THAT(sakuse.omn_,        0U);
    //EXPECT_THAT(sakuse.opn_,        0U);

    EXPECT_THAT(distsak.empty_,     Eq(false));
    EXPECT_THAT(distsak.header_,    Eq(true));
    EXPECT_THAT(distsak.cipher_,    Eq(MKA_CS_ID_GCM_AES_256));
    EXPECT_THAT(distsak.dan_,       Eq(cp_dist_an));
    EXPECT_THAT(distsak.conf_off_,  Eq(1U));
    EXPECT_THAT(distsak.keynum_,    Eq(1U));
    EXPECT_THAT(distsak.wrap_,      MemoryWith<uint8_t>(sak_wrapped, 40U));

    EXPECT_THAT(MKA_KAY_GetProtectFrames(0),                Eq(true));
    EXPECT_THAT(MKA_KAY_GetValidateFrames(0),               Eq(MKA_VALIDATE_STRICT));
}

TEST_F(TxDistSak, StopTransmittingWhenDistributted)
{
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);
    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(cp_dist_an), SetArgPointee<3>(false), SetArgPointee<4>(true)));
    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true);

    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_XPN);

    layersReset();
    SetPresentLayers(M_LPEERS + M_SAKUSE);
    sakuse.lrx_ = true;
    memset(sakuse.omi_, 0, sizeof(sakuse.omi_));

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer is now receiving with distributed SAK."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetAllReceiving(0, true)) .WillOnce(
        Invoke([this](t_MKA_bus bus, bool en) {
            static t_MKA_ki current_ki = {{0}, sakuse.lmn_};
            memcpy(current_ki.mi, sakuse.lmi_, sizeof(current_ki.mi));
            MKA_KAY_EnableTransmitSA(0, &current_ki);
            MKA_KAY_DeleteSAs(0, &null_ki);
        }));

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKA_EVENT_LINKUP"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_SECY_TransmitSA_EnableTransmit(0, _));
    EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, true));
    EXPECT_CALL(mocks, MKA_CP_GetProtectFrames(0)) .WillOnce(Return(true));
    EXPECT_CALL(mocks, MKA_CP_GetValidateFrames(0)) .WillOnce(Return(MKA_VALIDATE_STRICT));
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(cp_dist_an), SetArgPointee<3>(false), SetArgPointee<4>(true)));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    HandleTransmission();

    // SAK distribution complete
    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.lan_,        Eq(1));
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(true));
    EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.lmn_,        1U);
    EXPECT_THAT(sakuse.lpn_,        txsa.next_pn);

    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(false));
    // IRELEVANT: not in use
    //EXPECT_THAT(sakuse.oan_,        Eq(0));
    //EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>({0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
    //EXPECT_THAT(sakuse.omn_,        0U);
    //EXPECT_THAT(sakuse.opn_,        0U);
}

TEST_F(TxWhenServer, MetaTest)
{
}

TEST_F(TxWhenServer, SakUseWhenDistributingFirstKey)
{
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(1), SetArgPointee<3>(false), SetArgPointee<4>(true)));

    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true);

    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.lan_,        Eq(1));
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(true));
    EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.lmn_,        1U);
    EXPECT_THAT(sakuse.lpn_,        txsa.next_pn);

    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(false));
    // IRELEVANT: not in use
    //EXPECT_THAT(sakuse.oan_,        Eq(0));
    //EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>({0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
    //EXPECT_THAT(sakuse.omn_,        0U);
    //EXPECT_THAT(sakuse.opn_,        0U);
}

TEST_F(TxWhenServer, SakUseAfterDistributingFirstKey)
{
    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true, /*sc*/true, /*sak learn*/true);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKA_EVENT_LINKUP"), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_GetProtectFrames(0)) .WillOnce(Return(true));
    EXPECT_CALL(mocks, MKA_CP_GetValidateFrames(0)) .WillOnce(Return(MKA_VALIDATE_STRICT));
    txsa.next_pn = 23;
    HandleTransmission();

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    // Last key slot released
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(false));
    // IRELEVANT: not in use
    //EXPECT_THAT(sakuse.lan_,        Eq(0));
    //EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>({0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
    //EXPECT_THAT(sakuse.lmn_,        0U);
    //EXPECT_THAT(sakuse.lpn_,        0U);

    // Old key slot is now fully active
    EXPECT_THAT(sakuse.oan_,        Eq(1));
    EXPECT_THAT(sakuse.otx_,        Eq(true));
    EXPECT_THAT(sakuse.orx_,        Eq(true));
    EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.omn_,        1U);
    EXPECT_THAT(sakuse.opn_,        23);

    t_MKA_bus_info info;
    ASSERT_THAT(MKA_KAY_GetBusInfo(0U, &info), Eq(MKA_OK));
    ASSERT_THAT(info.status, Eq(MKA_STATUS_MACSEC_RUNNING));
}

TEST_F(TxWhenServer, FullSAKRotationOnExhaustion)
{
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKA_EVENT_LINKUP"), _)) .Times(1);
    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true, /*sc*/true, /*sak learn*/true);

    EXPECT_CALL(mocks, MKA_CP_GetProtectFrames(0)) .WillRepeatedly(Return(true));
    EXPECT_CALL(mocks, MKA_CP_GetValidateFrames(0)) .WillRepeatedly(Return(MKA_VALIDATE_STRICT));

    txsa.next_pn+=0x30000000UL; HandleTransmission(); // >3xxx xxxx
    txsa.next_pn+=0x30000000UL; HandleTransmission(); // >6xxx xxxx
    txsa.next_pn+=0x30000000UL; HandleTransmission(); // >9xxx xxxx
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Local participant reached PN exhaustion."), _)) .Times(1);
    txsa.next_pn+=0x30000000UL; HandleTransmission(); // >cxxx xxxx


    // let's invert SAK key test vectors
    uint8_t next_ks_nonce[32];
    uint8_t next_sak_wrapped[24];
    t_MKA_key next_sak = {{0}, 16U};

    for(int i=0; i<24; ++i) {
        next_sak_wrapped[i] = 0xFFU ^ sak_wrapped[i];
        if (i < 32) {
            next_ks_nonce[i] = 0xFFU ^ next_ks_nonce[i];
            next_sak.key[i] = 0xFFU ^ next_sak.key[i];
        }
    }
    t_MKA_ki old_ki; memcpy(old_ki.mi, participant->mi, sizeof(old_ki.mi));
    t_MKA_ki next_ki = old_ki;
    old_ki.kn = 1U;
    next_ki.kn = 2U;

    t_MKA_receive_sa    next_rxsa = {.in_use=true, .ssci=0, .next_pn=88, .lowest_pn=99};
    t_MKA_transmit_sa   next_txsa = {.in_use=true, .confidentiality=MKA_CONFIDENTIALITY_NONE, .ssci=0, .next_pn=11};

    EXPECT_CALL(mocks, MKA_GetRandomBytes(16, _))
            .WillOnce(DoAll(MemcpyToArg<1>((void*)next_ks_nonce, 16), Return(true)));
    EXPECT_CALL(mocks, MKA_DeriveSAK(
            /* cak          */ ObjectMatch(cak),
            /* ks_nonce     */ MemoryWith<uint8_t>(next_ks_nonce, 16U),
            /* mi           */ ObjectMatch(participant->mi),
            /* peer mi      */ MemoryWith<uint8_t>({6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1}),
            /* kn           */ 2U,
            /* out_len      */ 16U,
            /* sak          */ _
        )) .WillOnce(DoAll(
                MemcpyToArg<6>((void*)&next_sak, sizeof(next_sak)),
                Return(true)
        ));
    EXPECT_CALL(mocks, MKA_SECY_InstallKey(
            /* bus          */ 0,
            /* sak          */ ObjectMatch(next_sak),
            /* id           */ ObjectMatch(next_ki),
            /* tx/rx        */ true, true
        )) .WillOnce(Return((void*)12345));

    EXPECT_CALL(mocks, MKA_WrapKey(
            /* kek          */ ObjectMatch(kek),
            /* sak          */ ObjectMatch(next_sak),
            /* out wrapped  */ _)
            ) .WillOnce(DoAll(
                    MemcpyToArg<2>(next_sak_wrapped, 24U),
                    Return(true))
            );

    EXPECT_CALL(mocks, MKA_CP_SetCipherSuite(0, _));
    EXPECT_CALL(mocks, MKA_CP_SetCipherOffset(0, _));
    EXPECT_CALL(mocks, MKA_CP_SetDistributedKI(0, ObjectMatch(next_ki)));
    EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, 2));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&next_ki), SetArgPointee<2>(2), SetArgPointee<3>(false), SetArgPointee<4>(true)));
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&old_ki), SetArgPointee<2>(1), SetArgPointee<3>(true), SetArgPointee<4>(true)));
    EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0)) .WillOnce(
        Invoke([this, &old_ki, &next_ki](t_MKA_bus bus) { // lambdas as actions capturing this object, marvellous!!
            MKA_KAY_CreateSAs(bus, &next_ki);
            MKA_KAY_EnableReceiveSAs(bus, &next_ki);
        }));
    EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSA(0, 2, 1, _, _, _)) .WillOnce(Return(&next_txsa));
    EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSA(0, 2, 1, _, _)) .WillOnce(Return(&next_rxsa));
    EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_EnableReceive(0, &next_rxsa));
    EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, true));
    // here comes the storm of calls due to key rotation
    HandleTransmission();

    // check result
    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_XPN);

    EXPECT_THAT(distsak.empty_,     Eq(false));
    EXPECT_THAT(distsak.header_,    Eq(false));
    EXPECT_THAT(distsak.cipher_,    Eq(MKA_CS_ID_GCM_AES_128));
    EXPECT_THAT(distsak.dan_,       Eq(2));
    EXPECT_THAT(distsak.conf_off_,  Eq(1U));
    EXPECT_THAT(distsak.keynum_,    Eq(2U));
    EXPECT_THAT(distsak.wrap_,      MemoryWith<uint8_t>(next_sak_wrapped, 24U));

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.lan_,        Eq(2));
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(true));
    EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.lmn_,        2U);
    EXPECT_THAT(sakuse.lpn_,        next_txsa.next_pn);

    EXPECT_THAT(sakuse.oan_,        Eq(1));
    EXPECT_THAT(sakuse.otx_,        Eq(true));
    EXPECT_THAT(sakuse.orx_,        Eq(true));
    EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.omn_,        1U);
    EXPECT_THAT(sakuse.opn_,        txsa.next_pn);

    // now let's simulate we learn the new key and start receiving

    layersReset();
    SetPresentLayers(M_LPEERS + M_SAKUSE);
    lpeers.mn_ = participant->mn;
    sakuse.orx_ = true;
    sakuse.otx_ = true;
    sakuse.opn_ = 1U;
    sakuse.omn_ = 1U;
    sakuse.oan_ = 1U;
    sakuse.lrx_ = true;
    sakuse.ltx_ = false;
    sakuse.lpn_ = 1U;
    sakuse.lmn_ = 2U;
    sakuse.lan_ = 2U;

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Peer is now receiving with distributed SAK."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&next_ki), SetArgPointee<2>(2), SetArgPointee<3>(true), SetArgPointee<4>(true)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&old_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    EXPECT_CALL(mocks, MKA_CP_SetAllReceiving(0, true)) .WillOnce(
        Invoke([&next_ki, &old_ki](t_MKA_bus bus, bool en) {
            MKA_KAY_EnableTransmitSA(0, &next_ki);
            MKA_KAY_DeleteSAs(0, &old_ki);
        }));

    EXPECT_CALL(mocks, MKA_SECY_DestroyReceiveSA(0, &rxsa));
    EXPECT_CALL(mocks, MKA_SECY_DestroyTransmitSA(0, &txsa));
    EXPECT_CALL(mocks, MKA_SECY_TransmitSA_EnableTransmit(0, &next_txsa));
    EXPECT_CALL(mocks, MKA_CP_SetUsingTransmitSA(0, true));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    HandleTransmission();

    // SAK rotation completed
    // check result
    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(false));
    // IRELEVANT: not in use
    //EXPECT_THAT(sakuse.lan_,        Eq(0));
    //EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>({0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
    //EXPECT_THAT(sakuse.lmn_,        0U);
    //EXPECT_THAT(sakuse.lpn_,        0U);

    EXPECT_THAT(sakuse.oan_,        Eq(2));
    EXPECT_THAT(sakuse.otx_,        Eq(true));
    EXPECT_THAT(sakuse.orx_,        Eq(true));
    EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.omn_,        2U);
    EXPECT_THAT(sakuse.opn_,        next_txsa.next_pn);
}

TEST_F(TxWhenClient, MetaTest)
{
}

// TODO: Test when kay is key client
TEST_F(TxWhenClient, InstallSak)
{
    layersReset();
    ctx->role = MKA_ROLE_FORCE_KEY_CLIENT; // Configure kay as key client
    bps.key_server_ = true; // Announce peer as server
    distsak.dan_ = 3;
    SetPresentLayers(M_PPEERS + M_DISTSAK);

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New potential peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("New live peer"), _)) .Times(1);
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Elected peer as key server."), _)) .Times(1);
    EXPECT_CALL(mocks, MKA_CP_SetElectedSelf(0, false));
    EXPECT_CALL(mocks, MKA_CP_SignalChgdServer(0));
    EXPECT_CALL(mocks, MKA_LOGON_SetKayConnectMode(0, MKA_SECURED));


    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Registering new SAK-nonce pair for received SAK"), _)) .Times(1);
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
    EXPECT_CALL(mocks, MKA_CP_SetDistributedAN(0, 3));
    EXPECT_CALL(mocks, MKA_CP_SignalNewSAK(0)) .WillOnce(
        Invoke([identifier](t_MKA_bus bus) { // lambdas as actions capturing this object, marvellous!!
#if 0
            if (secure_channel) {
#endif
            {
                MKA_KAY_CreateSAs(bus, &identifier);
                MKA_KAY_EnableReceiveSAs(bus, &identifier);
            }
#if 0
            MKA_KAY_SetLatestSA(bus, &identifier, 3, false, true);
            MKA_KAY_SetOldSA(bus, &null_ki, 0U, false, false);
#endif
        }));
#if 0
    if (secure_channel)
#endif
    {
        //EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSC(0, ObjectMatch(ctx->actor_sci))) .WillOnce(Return(&txsc));
        EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSC(0, ObjectMatch(peer->sci))) .WillOnce(Return(&rxsc));
        EXPECT_CALL(mocks, MKA_SECY_CreateTransmitSA(0, 3, 1, _, _, _)) .WillOnce(Return(&txsa));
        EXPECT_CALL(mocks, MKA_SECY_CreateReceiveSA(0, 3, 1, _, _)) .WillOnce(Return(&rxsa));
        EXPECT_CALL(mocks, MKA_SECY_ReceiveSA_EnableReceive(0, &rxsa));
        EXPECT_CALL(mocks, MKA_CP_SetUsingReceiveSAs(0, true));
    }
    EXPECT_CALL(mocks, MKA_CP_GetProtectFrames(0)) .WillOnce(Return(true));
    EXPECT_CALL(mocks, MKA_CP_GetValidateFrames(0)) .WillOnce(Return(MKA_VALIDATE_STRICT));
    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&identifier), SetArgPointee<2>(3), SetArgPointee<3>(false), SetArgPointee<4>(true)));
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    FeedFrame(/*serialise*/true, /*handle_icv*/true);

    HandleTransmission();

    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.lan_,        Eq(3));
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(true));
    EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>(identifier.mi, sizeof(identifier.mi)));
    EXPECT_THAT(sakuse.lmn_,        1U);
    EXPECT_THAT(sakuse.lpn_,        txsa.next_pn);

    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(false));
    // IRELEVANT: not in use
    //EXPECT_THAT(sakuse.oan_,        Eq(0));
    //EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>({0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
    //EXPECT_THAT(sakuse.omn_,        0U);
    //EXPECT_THAT(sakuse.opn_,        0U);
}

TEST_F(TxAnnouncement, MetaTest)
{
}

TEST_F(TxAnnouncement, NoCipherSuites)
{
    HandleTransmission();
    ExpectPresentLayers(M_NONE);
}

TEST_F(TxAnnouncement, NoMACsec)
{
    ctx->macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
    HandleTransmission();
    ExpectPresentLayers(M_NONE);
}

TEST_F(TxAnnouncement, DefaultOnly)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_128;
    HandleTransmission();
    ExpectPresentLayers(M_ANN);
}

TEST_F(TxAnnouncement, OneNonDefault)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_128;
    HandleTransmission();
    ExpectPresentLayers(M_ANN);
    ASSERT_THAT(ann.content_len_,   2+1*10);
    EXPECT_THAT(ann.content_[0],    Eq(112<<1));
    ASSERT_THAT(ann.content_[1],    Eq(1*10));
    EXPECT_THAT(&ann.content_[2],   MemoryWith<uint8_t>({ 0x00U, 0x02U })); // integrity + confidentiality offset 0
    EXPECT_THAT(&ann.content_[4],   MemoryWith<uint8_t>({ 0x00U, 0x80U, 0xC2U, 0x00U, 0x01U, 0x00U, 0x00U, 0x03U })); // aes128-xpn
}

TEST_F(TxAnnouncement, TwoCiphers)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_256;
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_128;
    HandleTransmission();
    ExpectPresentLayers(M_ANN);

    ASSERT_THAT(ann.content_len_,   2+2*10);
    EXPECT_THAT(ann.content_[0],    Eq(112<<1));
    ASSERT_THAT(ann.content_[1],    Eq(2*10));
    EXPECT_THAT(&ann.content_[ 2],  MemoryWith<uint8_t>({ 0x00U, 0x03U })); // integrity + confidentiality multiple offsets
    EXPECT_THAT(&ann.content_[ 4],  MemoryWith<uint8_t>({ 0x00U, 0x80U, 0xC2U, 0x00U, 0x01U, 0x00U, 0x00U, 0x02U })); // aes256
    EXPECT_THAT(&ann.content_[12],  MemoryWith<uint8_t>({ 0x00U, 0x03U })); // integrity + confidentiality multiple offsets
    EXPECT_THAT(&ann.content_[14],  MemoryWith<uint8_t>({ 0x00U, 0x80U, 0xC2U, 0x00U, 0x01U, 0x00U, 0x00U, 0x01U })); // aes128
}


TEST_F(TxAnnouncement, FourCiphers)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256;
    test_buses_active_config.impl.cipher_preference[1] = MKA_CS_ID_GCM_AES_XPN_128;
    test_buses_active_config.impl.cipher_preference[2] = MKA_CS_ID_GCM_AES_256;
    test_buses_active_config.impl.cipher_preference[3] = MKA_CS_ID_GCM_AES_128;
    HandleTransmission();
    ExpectPresentLayers(M_ANN);

    ASSERT_THAT(ann.content_len_,   2+4*10);
    EXPECT_THAT(ann.content_[0],    Eq(112<<1));
    ASSERT_THAT(ann.content_[1],    Eq(4*10));
    EXPECT_THAT(&ann.content_[ 2],  MemoryWith<uint8_t>({ 0x00U, 0x02U })); // integrity + confidentiality offset 0
    EXPECT_THAT(&ann.content_[ 4],  MemoryWith<uint8_t>({ 0x00U, 0x80U, 0xC2U, 0x00U, 0x01U, 0x00U, 0x00U, 0x04U })); // aes256-xpn
    EXPECT_THAT(&ann.content_[12],  MemoryWith<uint8_t>({ 0x00U, 0x02U })); // integrity + confidentiality offset 0
    EXPECT_THAT(&ann.content_[14],  MemoryWith<uint8_t>({ 0x00U, 0x80U, 0xC2U, 0x00U, 0x01U, 0x00U, 0x00U, 0x03U })); // aes128-xpn
    EXPECT_THAT(&ann.content_[22],  MemoryWith<uint8_t>({ 0x00U, 0x03U })); // integrity + confidentiality multiple offsets
    EXPECT_THAT(&ann.content_[24],  MemoryWith<uint8_t>({ 0x00U, 0x80U, 0xC2U, 0x00U, 0x01U, 0x00U, 0x00U, 0x02U })); // aes256
    EXPECT_THAT(&ann.content_[32],  MemoryWith<uint8_t>({ 0x00U, 0x03U })); // integrity + confidentiality multiple offsets
    EXPECT_THAT(&ann.content_[34],  MemoryWith<uint8_t>({ 0x00U, 0x80U, 0xC2U, 0x00U, 0x01U, 0x00U, 0x00U, 0x01U })); // aes128
}

TEST_F(TxXPN, MetaTest)
{
}

TEST_F(TxXPN, ExtendedExhaustion)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256;
    EXPECT_CALL(mocks, print_action(LoggingMessageContains("MKA_EVENT_LINKUP"), _)) .Times(1);
    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true, /*sc*/true, /*sak learn*/true);

    EXPECT_CALL(mocks, MKA_CP_GetProtectFrames(0)) .WillRepeatedly(Return(true));
    EXPECT_CALL(mocks, MKA_CP_GetValidateFrames(0)) .WillRepeatedly(Return(MKA_VALIDATE_STRICT));

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Local participant reached PN exhaustion."), _)) .Times(0);

    txsa.next_pn = 0xC0000001ULL;
    HandleTransmission();
    txsa.next_pn = 0xBFFFFFFFFFFFFFFFULL;
    HandleTransmission();

    EXPECT_CALL(mocks, print_action(LoggingMessageContains("Local participant reached PN exhaustion."), _)) .Times(1);

    txsa.next_pn = 0xC000000000000000ULL;
    HandleTransmission();
}

TEST_F(TxXPN, ExtendedTransmittedLatest)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256;
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(1), SetArgPointee<3>(false), SetArgPointee<4>(true)));

    EXPECT_CALL(mocks, MKA_SECY_TransmitSA_UpdateNextPN(0U, &txsa));
    txsa.next_pn = 0x1111222233445566ULL;

    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true);

    ASSERT_THAT(participant->cipher, Eq(MKA_CS_ID_GCM_AES_XPN_256));
    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_ANN + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.lan_,        Eq(1));
    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(true));
    EXPECT_THAT(sakuse.lmi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.lmn_,        1U);
    EXPECT_THAT(sakuse.lpn_,        0x33445566UL);
    EXPECT_THAT(xpn.l_hpn,          0x11112222UL);

    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(false));
}

TEST_F(TxXPN, ExtendedTransmittedOld)
{
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_XPN_256;
    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(1), SetArgPointee<3>(false), SetArgPointee<4>(true)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));

    EXPECT_CALL(mocks, MKA_SECY_TransmitSA_UpdateNextPN(0U, &txsa));
    txsa.next_pn = 0x33331111AABBCCDDULL;

    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true);

    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_ANN + M_XPN);

    EXPECT_THAT(sakuse.plain_tx_,   Eq(false));
    EXPECT_THAT(sakuse.plain_rx_,   Eq(false));
    EXPECT_THAT(sakuse.delay_prot_, Eq(true));

    EXPECT_THAT(sakuse.oan_,        Eq(1));
    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(true));
    EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.omn_,        1U);
    EXPECT_THAT(sakuse.opn_,        0xAABBCCDDUL);
    EXPECT_THAT(xpn.o_hpn,          0x33331111UL);

    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(false));
}

TEST_F(TxXPN, XpnOptionallyNotTransmittedWithoutXpnCipher)
{
    test_global_active_config.transmit_null_xpn = false;
    test_buses_active_config.impl.cipher_preference[0] = MKA_CS_ID_GCM_AES_128;
    participant->cipher = MKA_CS_ID_GCM_AES_128; // non-XPN cipher

    // Transmission will happen right after reception
    HandlePreTransmission(/*handle_icv*/true, /*handle_rx*/false);

    // Simulate usage of key
    EXPECT_CALL(mocks, MKA_CP_GetOldSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&cp_dist_ki), SetArgPointee<2>(1), SetArgPointee<3>(false), SetArgPointee<4>(true)));
    EXPECT_CALL(mocks, MKA_CP_GetLatestSA(0, /*ki*/_, /*an*/_, /*tx*/_, /*rx*/_)) .Times(2) .WillRepeatedly(DoAll(
        SetArgPointee<1>(&null_ki), SetArgPointee<2>(0), SetArgPointee<3>(false), SetArgPointee<4>(false)));

    EXPECT_CALL(mocks, MKA_SECY_TransmitSA_UpdateNextPN(0U, &txsa));
    txsa.next_pn = 0x000000000ABBCCDDULL;

    learnPeerAsKeyServer(/* layer rst */true, /*sak_wrapped*/true);

    ExpectPresentLayers(M_LPEERS + M_SAKUSE + M_DISTSAK + M_ANN/* + M_XPN */);

    EXPECT_THAT(sakuse.oan_,        Eq(1));
    EXPECT_THAT(sakuse.otx_,        Eq(false));
    EXPECT_THAT(sakuse.orx_,        Eq(true));
    EXPECT_THAT(sakuse.omi_,        MemoryWith<uint8_t>(participant->mi, sizeof(participant->mi)));
    EXPECT_THAT(sakuse.omn_,        1U);
    EXPECT_THAT(sakuse.opn_,        0x0ABBCCDDUL);

    EXPECT_THAT(sakuse.ltx_,        Eq(false));
    EXPECT_THAT(sakuse.lrx_,        Eq(false));
}
