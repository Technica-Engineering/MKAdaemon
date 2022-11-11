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
    CMocks(void) {
        assert(((void)"Duplicated object!", (inst==NULL)));
        inst = this;
    }
    ~CMocks(void) {
        inst = NULL;
    }

    static CMocks* get(void) {
        assert(((void)"UT error: object Mocks not instantiated", (CMocks::inst != NULL)));
        return inst;
    }

    // utils
    MOCK_METHOD0( assertion_action, void(void));
    MOCK_METHOD2( print_action, void(char const*, unsigned long));
    MOCK_METHOD2( event_action, void(t_MKA_bus, t_MKA_event));

    MOCK_METHOD4( MKA_DeriveKEK, bool(t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*));
    MOCK_METHOD5( MKA_DeriveICK, bool(uint32_t, t_MKA_key const*, t_MKA_ckn const*, uint32_t, t_MKA_key*));
    /* Driver */
    MOCK_METHOD3( MKA_PHY_UpdateSecY, t_MKA_result(t_MKA_bus, t_MKA_SECY_config const *, t_MKA_sci const *));
    MOCK_METHOD2( MKA_PHY_InitRxSC,   t_MKA_result(t_MKA_bus, t_MKA_sci const *));
    MOCK_METHOD2( MKA_PHY_UpdateRxSC, t_MKA_result(t_MKA_bus, t_MKA_sci const *));
    MOCK_METHOD2( MKA_PHY_DeinitRxSC, t_MKA_result(t_MKA_bus, t_MKA_sci const *));
    MOCK_METHOD9( MKA_PHY_AddTxSA,    t_MKA_result(t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, t_MKA_key const *, t_MKA_key const *, t_MKA_key const *, t_MKA_ki const *, bool));
    MOCK_METHOD4( MKA_PHY_UpdateTxSA, t_MKA_result(t_MKA_bus, uint8_t, t_MKA_pn, bool));
    MOCK_METHOD2( MKA_PHY_DeleteTxSA, t_MKA_result(t_MKA_bus, uint8_t));
    MOCK_METHOD9( MKA_PHY_AddRxSA,    t_MKA_result(t_MKA_bus, uint8_t, t_MKA_pn, t_MKA_ssci, t_MKA_key const *, t_MKA_key const *, t_MKA_key const *, t_MKA_ki const *, bool));
    MOCK_METHOD4( MKA_PHY_UpdateRxSA, t_MKA_result(t_MKA_bus, uint8_t, t_MKA_pn, bool));
    MOCK_METHOD2( MKA_PHY_DeleteRxSA, t_MKA_result(t_MKA_bus, uint8_t));
    MOCK_METHOD3( MKA_PHY_GetTxSANextPN, t_MKA_result(t_MKA_bus, uint8_t, t_MKA_pn*));
    MOCK_METHOD5( MKA_PHY_GetMacSecStats, t_MKA_result(t_MKA_bus, t_MKA_stats_transmit_secy*, t_MKA_stats_receive_secy*, t_MKA_stats_transmit_sc*, t_MKA_stats_receive_sc*));
};

#endif // MOCKS_H_

