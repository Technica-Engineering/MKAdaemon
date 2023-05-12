/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_phy_driver.h
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
/****** Copyright 2021 Technica Engineering ******************************//**
 * @file        mka_phy_driver.h
 * @version     1.0.0
 * @author      Jordi Augé
 * @brief       SecY interface to Linux libnl
 *
 * @{
 */

#ifndef MKA_PHY_DRIVER_H
#define MKA_PHY_DRIVER_H





t_MKA_result libnl_init(void);
t_MKA_result libnl_deinit(void);


t_MKA_result MKA_PHY_UpdateSecY(t_MKA_bus bus, t_MKA_SECY_config const * config, t_MKA_sci const * tx_sci);
t_MKA_result MKA_PHY_InitRxSC(t_MKA_bus bus, t_MKA_sci const * sci);
t_MKA_result MKA_PHY_DeinitRxSC(t_MKA_bus bus, t_MKA_sci const * sci);
t_MKA_result MKA_PHY_AddTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active);
t_MKA_result MKA_PHY_UpdateTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active);
t_MKA_result MKA_PHY_DeleteTxSA(t_MKA_bus bus, uint8_t an);
t_MKA_result MKA_PHY_AddRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active);
t_MKA_result MKA_PHY_UpdateRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active);
t_MKA_result MKA_PHY_DeleteRxSA(t_MKA_bus bus, uint8_t an);
t_MKA_result MKA_PHY_GetTxSANextPN(t_MKA_bus bus, uint8_t an, t_MKA_pn* next_pn);
t_MKA_result MKA_PHY_GetMacSecStats(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy,
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc);



#endif

/** @} */

