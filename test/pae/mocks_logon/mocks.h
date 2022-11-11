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

#include <assert.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mka_private.h"

namespace Mock {

class Mocks {
   public:
    /* Enforce single object at a time */
    static Mocks *inst;
    Mocks(void)
    {
        assert(((void)"You have several mock objects. Only one object can exist at a time.", (inst == NULL)));
        inst = this;
    }
    ~Mocks(void)
    {
        inst = NULL;
    }

    MOCK_METHOD2( event_action, void(t_MKA_bus, t_MKA_event));

    /* Integration */
    MOCK_METHOD3( MKA_RetrieveCAKCKN, t_MKA_result(t_MKA_bus, t_MKA_key * const, t_MKA_ckn * const));
    MOCK_METHOD2( MKA_RetrieveKEK, t_MKA_result(t_MKA_bus, t_MKA_key * const));
    MOCK_METHOD2( MKA_RetrieveICK, t_MKA_result(t_MKA_bus, t_MKA_key * const));

    /* KaY */
    MOCK_METHOD7( MKA_KAY_CreateMKA, bool(t_MKA_bus, t_MKA_ckn const*, t_MKA_key const*, t_MKA_key const*, t_MKA_key const*, void const*, uint32_t));
    MOCK_METHOD1( MKA_KAY_DeleteMKA, void(t_MKA_bus));
    MOCK_METHOD2( MKA_KAY_Participate, void(t_MKA_bus,bool));

    /* CP */
    MOCK_METHOD1( MKA_CP_ConnectPending, void(t_MKA_bus));
    MOCK_METHOD1( MKA_CP_ConnectUnauthenticated, void(t_MKA_bus));
    MOCK_METHOD1( MKA_CP_ConnectAuthenticated, void(t_MKA_bus));
    MOCK_METHOD1( MKA_CP_ConnectSecure, void(t_MKA_bus));
};


}  // namespace Mock

#endif /* MOCKS_H_ */
