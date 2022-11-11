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

/* KaY */
bool MKA_KAY_GetProtectFrames(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_KAY_GetProtectFrames(bus); 
}

t_MKA_validate_frames MKA_KAY_GetValidateFrames(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_KAY_GetValidateFrames(bus); 
}

bool MKA_KAY_GetReplayProtect(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_KAY_GetReplayProtect(bus); 
}

uint32_t MKA_KAY_GetReplayWindow(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_KAY_GetReplayWindow(bus); 
}

void MKA_KAY_CreateSAs(t_MKA_bus bus, t_MKA_ki const* ki)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_KAY_CreateSAs(bus, ki); 
}

void MKA_KAY_EnableReceiveSAs(t_MKA_bus bus, t_MKA_ki const* ki)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_KAY_EnableReceiveSAs(bus, ki); 
}

void MKA_KAY_EnableTransmitSA(t_MKA_bus bus, t_MKA_ki const* ki)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_KAY_EnableTransmitSA(bus, ki); 
}

void MKA_KAY_DeleteSAs(t_MKA_bus bus, t_MKA_ki const* ki)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_KAY_DeleteSAs(bus, ki); 
}

void MKA_KAY_SignalNewInfo(t_MKA_bus bus)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_KAY_SignalNewInfo(bus); 
}

/* SecY */
t_MKA_result MKA_SECY_UpdateConfiguration(t_MKA_bus bus, const t_MKA_SECY_config * config)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_SECY_UpdateConfiguration(bus, config); 
}

} /* extern "C" */
