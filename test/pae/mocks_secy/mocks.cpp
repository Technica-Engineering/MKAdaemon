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

/* Crypto */
void * aes_encrypt_init(const uint8_t *key, size_t len)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->aes_encrypt_init(key, len);
}
int32_t aes_encrypt(void *ctx, const uint8_t *plain, uint8_t *crypt)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->aes_encrypt(ctx, plain, crypt);
}
void aes_encrypt_deinit(void *ctx)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->aes_encrypt_deinit(ctx);
}
/* Driver */
t_MKA_result MKA_PHY_UpdateSecY(t_MKA_bus bus, t_MKA_SECY_config const * config, t_MKA_sci const * tx_sci)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_UpdateSecY(bus, config, tx_sci);
}
t_MKA_result MKA_PHY_InitRxSC(t_MKA_bus bus, t_MKA_sci const * sci)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_InitRxSC(bus, sci);
}
t_MKA_result MKA_PHY_UpdateRxSC(t_MKA_bus bus, t_MKA_sci const * sci)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_UpdateRxSC(bus, sci);
}
t_MKA_result MKA_PHY_DeinitRxSC(t_MKA_bus bus, t_MKA_sci const * sci)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_DeinitRxSC(bus, sci);
}
t_MKA_result MKA_PHY_AddTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_AddTxSA(bus, an, next_pn, ssci, sak, hash, salt, ki, active);
}
t_MKA_result MKA_PHY_UpdateTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_UpdateTxSA(bus, an, next_pn, active);
}
t_MKA_result MKA_PHY_DeleteTxSA(t_MKA_bus bus, uint8_t an)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_DeleteTxSA(bus, an);
}
t_MKA_result MKA_PHY_AddRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_AddRxSA(bus, an, next_pn, ssci, sak, hash, salt, ki, active);
}
t_MKA_result MKA_PHY_UpdateRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_UpdateRxSA(bus, an, next_pn, active);
}
t_MKA_result MKA_PHY_DeleteRxSA(t_MKA_bus bus, uint8_t an)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_DeleteRxSA(bus, an);
}

t_MKA_result MKA_PHY_GetTxSANextPN(t_MKA_bus bus, uint8_t an, t_MKA_pn* next_pn)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_GetTxSANextPN(bus, an, next_pn);
}

t_MKA_result MKA_PHY_GetMacSecStats(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy,
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    return Mocks::inst->MKA_PHY_GetMacSecStats(bus, stats_tx_secy, stats_rx_secy, stats_tx_sc, stats_rx_sc);
}

/* CP */
void MKA_CP_SetPortEnabled(t_MKA_bus bus, bool status)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_CP_SetPortEnabled(bus, status);
}
/* LOGON */
void MKA_LOGON_SetPortEnabled(t_MKA_bus bus, bool status)
{
    assert(((void)"UT error: object Mocks not instantiated", (Mocks::inst != NULL)));
    Mocks::inst->MKA_LOGON_SetPortEnabled(bus, status);
}

} /* extern "C" */
