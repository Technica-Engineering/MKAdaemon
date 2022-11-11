/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-sha1.cpp
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

#include <gtest/gtest.h>
#include "mka_private.h"

void print_sha1_mac(u8 *mac){
	printf("Sha1 MAC: ");
	for (int i=0;i<20;i++){
		printf("%x ", mac[i]);
	}
	printf("\n");
}

TEST(sha1, vector_single_hash) {
	int result;
	size_t num_elem = 1;
	const u8 data[] = {0x74, 0x65, 0x73, 0x74, 0x69 ,0x6e ,0x67};
	const u8 *addr[] = {data};
	const size_t len[] = {7};
	u8 mac[20];
	const u8 expected_mac[] = {
		0xdc, 0x72, 0x4a, 0xf1, 0x8f, 0xbd, 0xd4, 0xe5,
		0x91, 0x89, 0xf5, 0xfe, 0x76, 0x8a, 0x5f, 0x83,
		0x11, 0x52, 0x70, 0x50
	};
	result = sha1_vector(num_elem, addr, len, mac);
    ASSERT_EQ(0, result) << "sha1_vector function call results in error";

	result = memcmp(mac, expected_mac, 20);
    ASSERT_EQ(0, result) << "sha1_vector gave wrong result";
}

TEST(crypto_test, vector_two_hashes) {
	int result;
	size_t num_elem = 2;
	const u8 data_0[] = {0x74, 0x65, 0x73, 0x74, 0x69 ,0x6e ,0x67};
	const u8 data_1[] = {0x65, 0x7a, 0x6f, 0x72, 0x65, 0x7a, 0x6f, 0x72};
	const u8 *addr[] = {data_0, data_1};
	const size_t len[] = {7,8};
	u8 mac[20];
	const u8 expected_mac[] = {
		0x1c, 0xb7, 0x3b, 0x70, 0x81, 0x2b, 0x39, 0xa4,
		0x0b, 0x91, 0xcd, 0xfb, 0xee, 0xb4, 0x24, 0x9c,
		0xf1, 0x37, 0xd6, 0xb0
	};
	result = sha1_vector(num_elem, addr, len, mac);
    ASSERT_EQ(0, result) << "sha1_vector function call results in error";

	result = memcmp(mac, expected_mac, 20);
    ASSERT_EQ(0, result) << "sha1_vector gave wrong result";
}
