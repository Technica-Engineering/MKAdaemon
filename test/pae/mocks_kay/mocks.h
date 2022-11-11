/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mocks.h
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

#ifndef MOCKS_H_
#define MOCKS_H_

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "ut_helpers.h"
#include "mka_private.h"

struct CMocks {
    static CMocks* inst;
    CMocks(void);
    virtual ~CMocks(void);

    static CMocks* get(void) {
        assert(((void)"UT error: object Mocks not instantiated", (CMocks::inst != NULL)));
        return inst;
    }

    // utils
    MOCK_METHOD0( assertion_action, void(void));
    MOCK_METHOD2( print_action, void(char const*, unsigned long));
    MOCK_METHOD2( event_action, void(t_MKA_bus, t_MKA_event));

    // crypto
    //MOCK_METHOD4( omac1_aes_128, int32_t(uint8_t const*, uint8_t const*, size_t, uint8_t *));
    //MOCK_METHOD4( omac1_aes_256, int32_t(uint8_t const*, uint8_t const*, size_t, uint8_t *));

    //MOCK_METHOD5( aes_wrap, int32_t (const uint8_t *, size_t, uint32_t, const uint8_t *, uint8_t *));
    //MOCK_METHOD5( aes_unwrap, int32_t (const uint8_t *, size_t, uint32_t, const uint8_t *, uint8_t *));

    MOCK_METHOD4( MKA_DeriveKEK, bool(t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*));
    MOCK_METHOD5( MKA_DeriveICK, bool(uint32_t, t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*));
    MOCK_METHOD7( MKA_DeriveSAK, bool(t_MKA_key const*, uint8_t const*, uint8_t const*, uint8_t const*, uint32_t, uint32_t, t_MKA_key *));
    MOCK_METHOD5( MKA_ComputeICV, bool(uint32_t, t_MKA_key const*, uint8_t const*, uint32_t, uint8_t *));
    MOCK_METHOD3( MKA_WrapKey, bool(t_MKA_key const*, t_MKA_key const*, uint8_t*));
    MOCK_METHOD4( MKA_UnwrapKey, bool(t_MKA_key const*, uint8_t const*, uint32_t, t_MKA_key *));
    MOCK_METHOD2( MKA_GetRandomBytes, bool (uint32_t, uint8_t*));

    // l2
    MOCK_METHOD2( MKA_l2_init, t_MKA_result (t_MKA_bus, uint16_t));
    MOCK_METHOD1( MKA_l2_deinit, void (t_MKA_bus));
    MOCK_METHOD3( MKA_l2_transmit, t_MKA_result (t_MKA_bus, uint8_t const*, uint32_t));
    MOCK_METHOD3( MKA_l2_receive, t_MKA_result (t_MKA_bus, uint8_t *, uint32_t *));
    MOCK_METHOD2( MKA_l2_getLocalAddr, t_MKA_result (t_MKA_bus, uint8_t *));

    // secy
    MOCK_METHOD5( MKA_SECY_InstallKey,  void*(t_MKA_bus, t_MKA_key const*, t_MKA_ki const*, bool, bool));
    MOCK_METHOD2( MKA_SECY_CreateTransmitSC, t_MKA_transmit_sc*(t_MKA_bus, t_MKA_sci const*));
    MOCK_METHOD2( MKA_SECY_DestroyTransmitSC, void (t_MKA_bus, t_MKA_transmit_sc*));
    MOCK_METHOD6( MKA_SECY_CreateTransmitSA, t_MKA_transmit_sa*(t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, t_MKA_confidentiality_offset, void*));
    MOCK_METHOD2( MKA_SECY_DestroyTransmitSA, void (t_MKA_bus, t_MKA_transmit_sa*));
    MOCK_METHOD2( MKA_SECY_CreateReceiveSC, t_MKA_receive_sc*(t_MKA_bus, t_MKA_sci const*));
    MOCK_METHOD2( MKA_SECY_DestroyReceiveSC, void (t_MKA_bus, t_MKA_receive_sc*));
    MOCK_METHOD5( MKA_SECY_CreateReceiveSA, t_MKA_receive_sa*(t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, void*));
    MOCK_METHOD2( MKA_SECY_DestroyReceiveSA, void (t_MKA_bus, t_MKA_receive_sa*));
    MOCK_METHOD2( MKA_SECY_ReceiveSA_EnableReceive, t_MKA_result(t_MKA_bus, t_MKA_receive_sa*));
    MOCK_METHOD2( MKA_SECY_TransmitSA_EnableTransmit, t_MKA_result(t_MKA_bus, t_MKA_transmit_sa*));
    MOCK_METHOD3( MKA_SECY_ReceiveSA_UpdateNextPN, void(t_MKA_bus, t_MKA_receive_sa*, t_MKA_pn));
    MOCK_METHOD2( MKA_SECY_TransmitSA_UpdateNextPN, t_MKA_result(t_MKA_bus, t_MKA_transmit_sa*));

    // cp
    MOCK_METHOD2( MKA_CP_SetCipherSuite, void(t_MKA_bus , uint64_t ));
    MOCK_METHOD2( MKA_CP_SetCipherOffset, void(t_MKA_bus , t_MKA_confidentiality_offset ));
    MOCK_METHOD2( MKA_CP_SetDistributedKI, void(t_MKA_bus , const t_MKA_ki * ));
    MOCK_METHOD2( MKA_CP_SetDistributedAN, void(t_MKA_bus , uint8_t ));
    MOCK_METHOD2( MKA_CP_SetUsingReceiveSAs, void(t_MKA_bus , bool ));
    MOCK_METHOD2( MKA_CP_SetElectedSelf, void(t_MKA_bus , bool ));
    MOCK_METHOD2( MKA_CP_SetAllReceiving, void(t_MKA_bus , bool ));
    MOCK_METHOD2( MKA_CP_SetUsingTransmitSA, void(t_MKA_bus , bool ));
    MOCK_METHOD2( MKA_CP_SetServerTransmitting, void(t_MKA_bus , bool ));
    MOCK_METHOD1( MKA_CP_SignalChgdServer, void(t_MKA_bus ));
    MOCK_METHOD1( MKA_CP_SignalNewSAK, void(t_MKA_bus ));
    MOCK_METHOD1( MKA_CP_GetProtectFrames, bool(t_MKA_bus) );
    MOCK_METHOD1( MKA_CP_GetValidateFrames, t_MKA_validate_frames(t_MKA_bus) );
    MOCK_METHOD5( MKA_CP_GetOldSA, void(t_MKA_bus, t_MKA_ki const**, uint8_t*, bool*, bool*));
    MOCK_METHOD5( MKA_CP_GetLatestSA, void(t_MKA_bus, t_MKA_ki const**, uint8_t*, bool*, bool*));

    // logon
    MOCK_METHOD2( MKA_LOGON_SetKayEnabled, void (t_MKA_bus, bool));
    MOCK_METHOD7( MKA_LOGON_SignalCreatedMKA, void (t_MKA_bus, t_MKA_ckn const*, t_MKA_key const*, t_MKA_key const*, t_MKA_key const*, void const*, t_mka_timer));
    MOCK_METHOD1( MKA_LOGON_SignalDeletedMKA, void (t_MKA_bus));
    MOCK_METHOD2( MKA_LOGON_SetKayConnectMode, void (t_MKA_bus, t_MKA_connect_mode));
};

#endif // MOCKS_H_
