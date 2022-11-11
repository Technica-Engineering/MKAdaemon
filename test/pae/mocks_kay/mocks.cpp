/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mocks.cpp
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

#include "mocks.h"

CMocks* CMocks::inst = nullptr;
#define INST_MOCK_METHOD0(ret, fnc)  \
        extern "C" ret fnc(void) { return CMocks::get()->fnc(); }
#define INST_MOCK_METHOD1(ret, fnc, t1)  \
        extern "C" ret fnc(t1 a1) { return CMocks::get()->fnc(a1); }
#define INST_MOCK_METHOD2(ret, fnc, t1, t2)  \
        extern "C" ret fnc(t1 a1, t2 a2) { return CMocks::get()->fnc(a1, a2); }
#define INST_MOCK_METHOD3(ret, fnc, t1, t2, t3)  \
        extern "C" ret fnc(t1 a1, t2 a2, t3 a3) { return CMocks::get()->fnc(a1, a2, a3); }
#define INST_MOCK_METHOD4(ret, fnc, t1, t2, t3, t4)  \
        extern "C" ret fnc(t1 a1, t2 a2, t3 a3, t4 a4) { return CMocks::get()->fnc(a1, a2, a3, a4); }
#define INST_MOCK_METHOD5(ret, fnc, t1, t2, t3, t4, t5)  \
        extern "C" ret fnc(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5) { return CMocks::get()->fnc(a1, a2, a3, a4, a5); }
#define INST_MOCK_METHOD6(ret, fnc, t1, t2, t3, t4, t5, t6)  \
        extern "C" ret fnc(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6) { return CMocks::get()->fnc(a1, a2, a3, a4, a5, a6); }
#define INST_MOCK_METHOD7(ret, fnc, t1, t2, t3, t4, t5, t6, t7)  \
        extern "C" ret fnc(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7) { return CMocks::get()->fnc(a1, a2, a3, a4, a5, a6, a7); }

// NOTE: vim can transform methods defined via "MOCK_METHODx(..." to macros above selecting lines and using
// this expression :'<,'>normal 0f,ldf(F(pr,f)xIINST_

CMocks::CMocks(void)
{
    assert(((void)"Duplicated object!", (inst==NULL)));
    inst = this;
}
CMocks::~CMocks(void)
{
    inst = NULL;
}

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

    // crypto
    //INST_MOCK_METHOD4( int32_t, omac1_aes_128,uint8_t const*, uint8_t const*, size_t, uint8_t *);
    //INST_MOCK_METHOD4( int32_t, omac1_aes_256,uint8_t const*, uint8_t const*, size_t, uint8_t *);

    //INST_MOCK_METHOD5( int32_t , aes_wrap,const uint8_t *, size_t, uint32_t, const uint8_t *, uint8_t *);
    //INST_MOCK_METHOD5( int32_t , aes_unwrap,const uint8_t *, size_t, uint32_t, const uint8_t *, uint8_t *);

    INST_MOCK_METHOD4( bool, MKA_DeriveKEK,t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*);
    INST_MOCK_METHOD5( bool, MKA_DeriveICK,uint32_t, t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*);
    INST_MOCK_METHOD7( bool, MKA_DeriveSAK,t_MKA_key const*, uint8_t const*, uint8_t const*, uint8_t const*, uint32_t, uint32_t, t_MKA_key *);
    INST_MOCK_METHOD5( bool, MKA_ComputeICV,uint32_t, t_MKA_key const*, uint8_t const*, uint32_t, uint8_t *);
    INST_MOCK_METHOD3( bool, MKA_WrapKey,t_MKA_key const*, t_MKA_key const*, uint8_t*);
    INST_MOCK_METHOD4( bool, MKA_UnwrapKey,t_MKA_key const*, uint8_t const*, uint32_t, t_MKA_key *);
    INST_MOCK_METHOD2( bool, MKA_GetRandomBytes, uint32_t, uint8_t*);

    // l2
    INST_MOCK_METHOD2( t_MKA_result , MKA_l2_init,t_MKA_bus, uint16_t);
    INST_MOCK_METHOD1( void , MKA_l2_deinit,t_MKA_bus);
    INST_MOCK_METHOD3( t_MKA_result , MKA_l2_transmit,t_MKA_bus, uint8_t const*, uint32_t);
    INST_MOCK_METHOD3( t_MKA_result , MKA_l2_receive,t_MKA_bus, uint8_t *, uint32_t *);
    INST_MOCK_METHOD2( t_MKA_result , MKA_l2_getLocalAddr,t_MKA_bus, uint8_t *);

    // secy
    INST_MOCK_METHOD5(  void*, MKA_SECY_InstallKey,t_MKA_bus, t_MKA_key const*, t_MKA_ki const*, bool, bool);
    INST_MOCK_METHOD2( t_MKA_transmit_sc*, MKA_SECY_CreateTransmitSC,t_MKA_bus, t_MKA_sci const*);
    INST_MOCK_METHOD2( void, MKA_SECY_DestroyTransmitSC, t_MKA_bus, t_MKA_transmit_sc*);
    INST_MOCK_METHOD6( t_MKA_transmit_sa*, MKA_SECY_CreateTransmitSA,t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, t_MKA_confidentiality_offset, void*);
    INST_MOCK_METHOD2( void, MKA_SECY_DestroyTransmitSA, t_MKA_bus, t_MKA_transmit_sa*);
    INST_MOCK_METHOD2( t_MKA_receive_sc*, MKA_SECY_CreateReceiveSC,t_MKA_bus, t_MKA_sci const*);
    INST_MOCK_METHOD2( void, MKA_SECY_DestroyReceiveSC, t_MKA_bus, t_MKA_receive_sc*);
    INST_MOCK_METHOD5( t_MKA_receive_sa*, MKA_SECY_CreateReceiveSA,t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, void*);
    INST_MOCK_METHOD2( void, MKA_SECY_DestroyReceiveSA, t_MKA_bus, t_MKA_receive_sa*);
    INST_MOCK_METHOD2( t_MKA_result, MKA_SECY_ReceiveSA_EnableReceive,t_MKA_bus, t_MKA_receive_sa*);
    INST_MOCK_METHOD2( t_MKA_result, MKA_SECY_TransmitSA_EnableTransmit,t_MKA_bus, t_MKA_transmit_sa*);
    INST_MOCK_METHOD3( void, MKA_SECY_ReceiveSA_UpdateNextPN, t_MKA_bus, t_MKA_receive_sa*, t_MKA_pn);
    INST_MOCK_METHOD2( t_MKA_result, MKA_SECY_TransmitSA_UpdateNextPN, t_MKA_bus, t_MKA_transmit_sa*);

    // cp
    INST_MOCK_METHOD2( void, MKA_CP_SetCipherSuite,t_MKA_bus , uint64_t );
    INST_MOCK_METHOD2( void, MKA_CP_SetCipherOffset,t_MKA_bus , t_MKA_confidentiality_offset );
    INST_MOCK_METHOD2( void, MKA_CP_SetDistributedKI,t_MKA_bus , const t_MKA_ki * );
    INST_MOCK_METHOD2( void, MKA_CP_SetDistributedAN,t_MKA_bus , uint8_t );
    INST_MOCK_METHOD2( void, MKA_CP_SetUsingReceiveSAs,t_MKA_bus , bool );
    INST_MOCK_METHOD2( void, MKA_CP_SetElectedSelf,t_MKA_bus , bool );
    INST_MOCK_METHOD2( void, MKA_CP_SetAllReceiving,t_MKA_bus , bool );
    INST_MOCK_METHOD2( void, MKA_CP_SetUsingTransmitSA,t_MKA_bus , bool );
    INST_MOCK_METHOD2( void, MKA_CP_SetServerTransmitting,t_MKA_bus , bool );
    INST_MOCK_METHOD1( void, MKA_CP_SignalChgdServer,t_MKA_bus );
    INST_MOCK_METHOD1( void, MKA_CP_SignalNewSAK,t_MKA_bus );
    INST_MOCK_METHOD1( bool, MKA_CP_GetProtectFrames,t_MKA_bus );
    INST_MOCK_METHOD1( t_MKA_validate_frames, MKA_CP_GetValidateFrames,t_MKA_bus );
    INST_MOCK_METHOD5( void, MKA_CP_GetOldSA, t_MKA_bus, t_MKA_ki const**, uint8_t*, bool*, bool*);
    INST_MOCK_METHOD5( void, MKA_CP_GetLatestSA, t_MKA_bus, t_MKA_ki const**, uint8_t*, bool*, bool*);

    // logon
    INST_MOCK_METHOD2( void, MKA_LOGON_SetKayEnabled, t_MKA_bus, bool);
    INST_MOCK_METHOD7( void, MKA_LOGON_SignalCreatedMKA, t_MKA_bus, t_MKA_ckn const*, t_MKA_key const*, t_MKA_key const*, t_MKA_key const*, void const*, t_mka_timer);
    INST_MOCK_METHOD1( void, MKA_LOGON_SignalDeletedMKA, t_MKA_bus);
    INST_MOCK_METHOD2( void, MKA_LOGON_SetKayConnectMode, t_MKA_bus, t_MKA_connect_mode);
