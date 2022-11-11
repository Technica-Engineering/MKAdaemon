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
#define INST_MOCK_METHOD8(ret, fnc, t1, t2, t3, t4, t5, t6, t7, t8)  \
        extern "C" ret fnc(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8) { return CMocks::get()->fnc(a1, a2, a3, a4, a5, a6, a7, a8); }
#define INST_MOCK_METHOD9(ret, fnc, t1, t2, t3, t4, t5, t6, t7, t8, t9)  \
        extern "C" ret fnc(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8, t9 a9) { return CMocks::get()->fnc(a1, a2, a3, a4, a5, a6, a7, a8, a9); }

// NOTE: vim can transform methods defined via "MOCK_METHODx(..." to macros above selecting lines and using
// this expression :'<,'>normal 0f,ldf(F(pr,f)xIINST_

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

    INST_MOCK_METHOD4( bool, MKA_DeriveKEK,t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*);
    INST_MOCK_METHOD5( bool, MKA_DeriveICK,uint32_t, t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*);
    INST_MOCK_METHOD3( t_MKA_result, MKA_PHY_UpdateSecY,t_MKA_bus, t_MKA_SECY_config const *, t_MKA_sci const *);
    INST_MOCK_METHOD2(   t_MKA_result, MKA_PHY_InitRxSC,t_MKA_bus, t_MKA_sci const *);
    INST_MOCK_METHOD2( t_MKA_result, MKA_PHY_UpdateRxSC,t_MKA_bus, t_MKA_sci const *);
    INST_MOCK_METHOD2( t_MKA_result, MKA_PHY_DeinitRxSC,t_MKA_bus, t_MKA_sci const *);
    INST_MOCK_METHOD9(    t_MKA_result, MKA_PHY_AddTxSA,t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, t_MKA_key const *, t_MKA_key const *, t_MKA_key const *, t_MKA_ki const *, bool);
    INST_MOCK_METHOD4( t_MKA_result, MKA_PHY_UpdateTxSA,t_MKA_bus, uint8_t, t_MKA_pn, bool);
    INST_MOCK_METHOD2( t_MKA_result, MKA_PHY_DeleteTxSA,t_MKA_bus, uint8_t);
    INST_MOCK_METHOD9(    t_MKA_result, MKA_PHY_AddRxSA,t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, t_MKA_key const *, t_MKA_key const *, t_MKA_key const *, t_MKA_ki const *, bool);
    INST_MOCK_METHOD4( t_MKA_result, MKA_PHY_UpdateRxSA,t_MKA_bus, uint8_t, t_MKA_pn, bool);
    INST_MOCK_METHOD2( t_MKA_result, MKA_PHY_DeleteRxSA,t_MKA_bus, uint8_t);
    INST_MOCK_METHOD3( t_MKA_result, MKA_PHY_GetTxSANextPN,t_MKA_bus, uint8_t, t_MKA_pn*);
    INST_MOCK_METHOD5( t_MKA_result, MKA_PHY_GetMacSecStats,t_MKA_bus, t_MKA_stats_transmit_secy*, t_MKA_stats_receive_secy*, t_MKA_stats_transmit_sc*, t_MKA_stats_receive_sc*);
