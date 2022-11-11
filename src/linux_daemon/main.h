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
 * @brief       MKA Linux launcher
 *
 * @{
 */

#ifndef MKA_LINUX_MAIN_H_
#define MKA_LINUX_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

void print_usage(void);
void daemon_main(void);
void write_log(char const* text, unsigned long length);
void signalHandlerSIGTERM(int sigio);

#ifdef __cplusplus
}
#endif

#endif /* MKA_LINUX_MAIN_H_ */
