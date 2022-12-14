/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-omac1.cpp
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

void print_omac1_mac(u8 *mac){
	printf("128-bit MAC: ");
	for (int i=0;i<16;i++){
		printf("%x ", mac[i]);
	}
	printf("\n");
}

TEST(aes_omac1, keylen_128bit) {
    //printf("Omac1 AES 128 Test 1 running.. ");
    int result;
    const u8 key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    u8 data[] = {
        0x32, 0x3a, 0x72, 0x8e, 0x79, 0x6f, 0xe0, 0xca,
        0x9f, 0x26, 0xd7, 0x7a, 0x85, 0x73, 0x73, 0x5a,
        0x98, 0xa3, 0xf8, 0xaf, 0x2a, 0x7c, 0xc3, 0xe1,
        0xa7, 0xe2, 0x6e, 0xd2, 0x8f, 0x4b, 0x8d, 0x3b,
        0x98, 0xa3, 0xf8, 0xaf, 0x2a, 0x7c, 0xc3, 0xe1,
        0xa7, 0xe2, 0x6e, 0xd2, 0x8f, 0x4b, 0x8d, 0x3b,
        0x98, 0xa3, 0xf8, 0xaf, 0x2a, 0x7c, 0xc3, 0xe1,
        0xa7, 0xe2, 0x6e, 0xd2, 0x8f, 0x4b, 0x8d, 0x3b};
    u8 expected_mac[] = {
        0x88, 0x7e, 0x6a, 0x9b, 0xf8, 0xa2, 0x0a, 0x6b,
        0x06, 0x77, 0xfd, 0x4e, 0x8d, 0xf3, 0xbd, 0xca};
    size_t data_len = 64;
    u8 mac[16];
    result = omac1_aes_128(key, data, data_len, mac);
    ASSERT_EQ(0, result) << "omac1_aes_128 function call results in error";

    //print_omac1_mac(mac);
    result = memcmp(mac, expected_mac, 16);
    ASSERT_EQ(0, result) << "omac1_aes_128 function call gave wrong result";
}

TEST(aes_omac1, keylen_256bit) {
    //printf("Omac1 AES 256 Test 1 running.. ");
    int result;
    const u8 key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    u8 data[] = {
        0x32, 0x3a, 0x72, 0x8e, 0x79, 0x6f, 0xe0, 0xca,
        0x9f, 0x26, 0xd7, 0x7a, 0x85, 0x73, 0x73, 0x5a,
        0x98, 0xa3, 0xf8, 0xaf, 0x2a, 0x7c, 0xc3, 0xe1,
        0xa7, 0xe2, 0x6e, 0xd2, 0x8f, 0x4b, 0x8d, 0x3b,
        0x98, 0xa3, 0xf8, 0xaf, 0x2a, 0x7c, 0xc3, 0xe1,
        0xa7, 0xe2, 0x6e, 0xd2, 0x8f, 0x4b, 0x8d, 0x3b,
        0x98, 0xa3, 0xf8, 0xaf, 0x2a, 0x7c, 0xc3, 0xe1,
        0xa7, 0xe2, 0x6e, 0xd2, 0x8f, 0x4b, 0x8d, 0x3b};
    u8 expected_mac[] = {
        0x3c, 0xf3, 0xb8, 0x0d, 0xa4, 0xbb, 0xaa, 0x28,
        0x0c, 0x0c, 0x83, 0x09, 0x82, 0x8c, 0xfe, 0x4f};
    size_t data_len = 64;
    u8 mac[16];
    result = omac1_aes_256(key, data, data_len, mac);
    ASSERT_EQ(0, result) << "omac1_aes_256 function call results in error";

    //print_omac1_mac(mac);
    result = memcmp(mac, expected_mac, sizeof(expected_mac));
    ASSERT_EQ(0, result) << "omac1_aes_256 function call gave wrong result";
}
