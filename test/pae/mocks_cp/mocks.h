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

#include "mka_kay.h"
#include "mka_secy.h"

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

    /* KaY */
    MOCK_METHOD1( MKA_KAY_GetProtectFrames, bool(t_MKA_bus));
    MOCK_METHOD1( MKA_KAY_GetValidateFrames, t_MKA_validate_frames(t_MKA_bus));
    MOCK_METHOD1( MKA_KAY_GetReplayProtect, bool(t_MKA_bus));
    MOCK_METHOD1( MKA_KAY_GetReplayWindow, uint32_t(t_MKA_bus));
    MOCK_METHOD2( MKA_KAY_CreateSAs, void(t_MKA_bus, t_MKA_ki const*));
    MOCK_METHOD2( MKA_KAY_EnableReceiveSAs, void(t_MKA_bus, t_MKA_ki const*));
    MOCK_METHOD2( MKA_KAY_EnableTransmitSA, void(t_MKA_bus, t_MKA_ki const*));
    MOCK_METHOD2( MKA_KAY_DeleteSAs, void(t_MKA_bus, t_MKA_ki const*));
    MOCK_METHOD1( MKA_KAY_SignalNewInfo, void(t_MKA_bus));

    /* SecY */
    MOCK_METHOD2( MKA_SECY_UpdateConfiguration, t_MKA_result(t_MKA_bus, const t_MKA_SECY_config *));
};


}  // namespace Mock

#endif /* MOCKS_H_ */
