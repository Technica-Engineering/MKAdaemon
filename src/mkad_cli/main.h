/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: main.h
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
/*******************************************************************************
 * @file        main.h
 * @version     1.0.0
 * @author      Jordi Auge
 * @brief       Mkad command line client main
 *
 * @{
 */

#ifndef MKAD_CLI_MAIN_H_
#define MKAD_CLI_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "gdbus-mkad-generated.h"

void print_usage(void);
const char* get_dbus_introspect_xml(void);
mkadBUS* get_mkad_proxy(char *active_bus);
void set_bus_enabled(mkadBUS* mkad_proxy, char* set_enabled);
void print_bus_info(mkadBUS* mkad_proxy);
void print_bus_stats(mkadBUS* mkad_proxy);

#ifdef __cplusplus
}
#endif

#endif /* MKAD_CLI_MAIN_H_ */
