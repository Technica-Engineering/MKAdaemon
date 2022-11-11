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

using Mock::Mocks;

/* Declare static variable */
Mocks *Mocks::inst = nullptr;

/* Now redirect C calls to C++ mocked object, with C linkage */
extern "C" {

void mock_event(t_MKA_bus bus, t_MKA_event event)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->event_action(bus, event);
}

/* Integration */
t_MKA_result MKA_RetrieveCAKCKN(t_MKA_bus bus, t_MKA_key * const cak, t_MKA_ckn * const ckn)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_RetrieveCAKCKN(bus, cak, ckn);
}

t_MKA_result MKA_RetrieveKEK(t_MKA_bus bus, t_MKA_key * const kek)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_RetrieveKEK(bus, kek);
}

t_MKA_result MKA_RetrieveICK(t_MKA_bus bus, t_MKA_key * const ick)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_RetrieveICK(bus, ick);
}

/* KaY */
bool MKA_KAY_CreateMKA(t_MKA_bus bus, t_MKA_ckn const*ckn, t_MKA_key const*cak, t_MKA_key const*kek,
                                t_MKA_key const*ick, void const*authdata, uint32_t life)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_KAY_CreateMKA(bus, ckn, cak, kek, ick, authdata, life);
}

void MKA_KAY_DeleteMKA(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_KAY_DeleteMKA(bus);
}

void MKA_KAY_Participate(t_MKA_bus bus, bool enable)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_KAY_Participate(bus, enable);
}

/* CP */
void MKA_CP_ConnectPending(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_CP_ConnectPending(bus);
}

void MKA_CP_ConnectUnauthenticated(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_CP_ConnectUnauthenticated(bus);
}

void MKA_CP_ConnectAuthenticated(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_CP_ConnectAuthenticated(bus);
}

void MKA_CP_ConnectSecure(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_CP_ConnectSecure(bus);
}

} /* extern "C" */
