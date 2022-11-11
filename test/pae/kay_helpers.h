/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: kay_helpers.h
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

#ifndef KAY_HELPERS_H_
#define KAY_HELPERS_H_

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <arpa/inet.h>
#include <new>

#include "ut_helpers.h"
#include "mka_kay_internal.h"
#include "mocks.h"


struct ILayer {
    static void ser16(uint8_t* where, uint16_t const& data) {
        where[0] = data >> 8U;
        where[1] = data;
    }
    static void ser32(uint8_t* where, uint32_t const& data) {
        ser16(&where[0], data >> 16U);
        ser16(&where[2], data);
    }
    static void ser64(uint8_t* where, uint64_t const& data) {
        ser32(&where[0], data >> 32U);
        ser32(&where[4], data);
    }
    static void des16(uint8_t const* data, uint16_t& out) {
        out = (uint16_t)data[0] << 8U | (uint16_t)data[1];
    }
    static void des32(uint8_t const* data, uint32_t& out) {
        uint16_t h, l;
        des16(&data[0], h); des16(&data[2], l);
        out = ((uint32_t)h << 16) + l;
    }
    static void des64(uint8_t const* data, uint64_t& out) {
        uint32_t h, l;
        des32(&data[0], h); des32(&data[4], l);
        out = ((uint64_t)h << 32) + l;
    }
    virtual void serialise(uint8_t* where) const = 0;
    virtual void deserialise(uint8_t const* data) = 0;
    virtual uint32_t getSize(void) const = 0;
};

struct MAC {
    uint8_t addr[6U];
};

struct EthHdr : public ILayer {
    MAC         src_ = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    MAC         dst_ = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    uint16_t    type_ = 0x888E;

    void serialise(uint8_t* where) const {
        memcpy(&where[0], dst_.addr, 6U);
        memcpy(&where[6], src_.addr, 6U);
        ser16(&where[12], type_);
    }
    void deserialise(uint8_t const* data) {
        memcpy(dst_.addr, &data[0], 6U);
        memcpy(src_.addr, &data[6], 6U);
        des16(&data[12], type_);
    }
    virtual uint32_t getSize(void) const { return 14U; }
    void reset(void) {
        new (this) EthHdr();
    }
};

struct EAPOLHdr : public ILayer {
    uint8_t version_    = 3;
    uint8_t type_       = 5U;
    uint16_t body_len_  = 0U;

    void serialise(uint8_t* where) const {
        where[0] = version_;
        where[1] = type_;
        ser16(&where[2], body_len_);
    }
    void deserialise(uint8_t const* data) {
        version_ = data[0];
        type_ = data[1];
        des16(&data[2], body_len_);
    }
    virtual uint32_t getSize(void) const { return 4U; }
    void reset(void) {
        new (this) EAPOLHdr();
    }
};

struct MkParameter : public ILayer {
    uint8_t type_;
    uint8_t first_byte_;
    uint8_t nibble_;
    uint16_t body_len_;
    MkParameter(uint8_t type, uint8_t first_byte, uint8_t nibble, uint16_t body_len) :
        type_(type), first_byte_(first_byte), nibble_(nibble), body_len_(body_len) {}
    MkParameter(uint8_t const*incoming) { deserialise(incoming); }

    void serialise(uint8_t* where) const {
        where[0] = type_;
        where[1] = first_byte_;
        where[2] = (nibble_ << 4U) | ((body_len_ >> 8U) & 0x0F);
        where[3] = body_len_;
    }
    void deserialise(uint8_t const* data) {
        type_ = data[0];
        first_byte_ = data[1];
        nibble_ = data[2] >> 4U;
        body_len_ = ((data[2] << 8U) & 0x0F00) | data[3];
    }
    virtual uint32_t getSize(void) const { return 4U; }
};

struct BPSHdr : public ILayer {
    bool present_       = true;
    uint8_t version_    = 3U;
    uint8_t priority_   = 128U;
    bool key_server_    = false;
    bool macsec_desired_= true;
    uint8_t macsec_cap_ = 2U;
    t_MKA_sci sci_      = {{0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}, 0x706};
    uint8_t mi_[12]     = {6, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 1};
    uint32_t mn_        = 0;
    uint32_t algo_      = 0x0080C201U;
    char const* ckn_    = "ab";

    char cak_space[128];
    void serialise(uint8_t* where) const {
        if (!present_) return;
        MkParameter hdr(version_, priority_, (key_server_ << 3U) | (macsec_desired_ << 2U) | macsec_cap_, 28U + strlen(ckn_));
        hdr.serialise(where);
        memcpy(&where[4], sci_.addr, 6U);
        ser16(&where[10], sci_.port);
        memcpy(&where[12], mi_, sizeof(mi_));
        ser32(&where[24], mn_);
        ser32(&where[28], algo_);
        memset(&where[32], 0, getSize() - 32);
        memcpy(&where[32], ckn_, strlen(ckn_));
    }
    void deserialise(uint8_t const* data) {
        present_ = true;
        MkParameter hdr(data);
        version_ = hdr.type_;
        priority_ = hdr.first_byte_;
        key_server_ = hdr.nibble_ >> 3U;
        macsec_desired_ = hdr.nibble_ >> 2U;
        macsec_cap_ = hdr.nibble_ & 0x3U;
        memcpy(sci_.addr, &data[4], 6U);
        uint16_t port; des16(&data[10], port); sci_.port = port;
        memcpy(mi_, &data[12], sizeof(mi_));
        des32(&data[24], mn_);
        des32(&data[28], algo_);
        ASSERT_TRUE(hdr.body_len_ >= 28U);
        memcpy(cak_space, &data[32], hdr.body_len_ - 28U);
        cak_space[hdr.body_len_ - 28U] = '\0';
        ckn_ = cak_space;
    }
    virtual uint32_t getSize(void) const { return present_*(4U + 28U + (strlen(ckn_)+3) & 0xFFFFFFFC); }
    void reset(void) {
        new (this) BPSHdr();
    }
};

struct GenericPeerList : public ILayer {
    bool present_       = true;
    uint8_t mi_[12U]    = {9, 12, 12, 12, 12, 12, 33, 44, 55, 66, 11, 12};
    uint32_t mn_        = 1U;
    uint32_t number_    = 1U;
    uint8_t type_       = 0U;
    int32_t invalid_sz_ = -1;
    GenericPeerList(uint8_t const&type) : type_(type) {}
    void serialise(uint8_t* where) const {
        if (!present_) return;
        MkParameter hdr(type_, /* TODO */ 0U, 0U, (invalid_sz_ >= 0) ? invalid_sz_ : (getSize() - 4));
        hdr.serialise(where);
        where+=4;
        for(int i=0; i<number_; ++i) {
            memcpy(where, mi_, 12U);
            ser32(&where[12], mn_);
            where += 16;
        }
    }
    void deserialise(uint8_t const* data) {
        present_ = (type_ == *data);
        invalid_sz_ = -1;
        if (!present_) {
            memset(mi_, 0, sizeof(mi_));
            mn_ = 0U;
            number_ = 0U;
        }
        else {
            MkParameter hdr(data);
            number_ = hdr.body_len_ / 16;
            data+=4;
            for(int i=0; i<number_; ++i) {
                memcpy(mi_, data, 12U);
                des32(&data[12], mn_);
                data += 16;
            }
        }
    }
    virtual uint32_t getSize(void) const { return present_*(4 + 16*number_); }
    void reset(void) {
        new (this) GenericPeerList(type_);
    }
};

struct LivePeerList : public GenericPeerList { LivePeerList(void) : GenericPeerList(1) {} };
struct PotentialPeerList : public GenericPeerList { PotentialPeerList(void) : GenericPeerList(2) {} };

struct SAKUse : public ILayer {
    bool present_       = true;
    bool empty_         = false;

    uint8_t     lan_        = 1;
    bool        ltx_        = false;
    bool        lrx_        = false;

    uint8_t     oan_        = 1;
    bool        otx_        = false;
    bool        orx_        = false;

    bool        plain_tx_   = false;
    bool        plain_rx_   = false;
    bool        delay_prot_ = false;
    
    uint8_t     lmi_[12U]   = {9, 12, 12, 12, 12, 12, 33, 44, 55, 66, 11, 12};
    uint32_t    lmn_        = 1U;
    uint32_t    lpn_        = 1U;

    uint8_t     omi_[12U]   = {9, 12, 12, 12, 12, 12, 33, 44, 55, 66, 11, 12};
    uint32_t    omn_        = 1U;
    uint32_t    opn_        = 1U;

    int32_t     invalid_sz_ = -1;

    void serialise(uint8_t* where) const {
        if (!present_) return;
        MkParameter hdr(3, (lan_ << 6) + (ltx_ << 5) + (lrx_ << 4) + (oan_ << 2) + (otx_ << 1) + orx_, 
                                    (plain_tx_ << 3) + (plain_rx_ << 2) + delay_prot_, 
                    (invalid_sz_ >= 0) ? invalid_sz_ : (empty_ ? 0U : (getSize() - 4)));
        hdr.serialise(where);
        if (!empty_) {
            memcpy(&where[4], lmi_, 12);
            ser32(&where[16], lmn_);
            ser32(&where[20], lpn_);

            memcpy(&where[24], omi_, 12);
            ser32(&where[36],  omn_);
            ser32(&where[40],  opn_);
        }
    }
    void deserialise(uint8_t const* data) {
        present_ = (3 == *data);
        invalid_sz_ = -1;
        if (!present_) {
            lan_ = 0U;
            ltx_ = 0U;
            lrx_ = 0U;
            oan_ = 0U;
            otx_ = 0U;
            orx_ = 0U;
            plain_tx_ = 0U;
            plain_rx_ = 0U;
            delay_prot_ = 0U;
            
            memset(lmi_, 0 , 12);
            lmn_ = 0U;
            lpn_ = 0U;

            memset(omi_, 0 , 12);
            omn_ = 0U;
            opn_ = 0U;
        }
        else {
            invalid_sz_ = -1;
            MkParameter hdr(data);
            empty_ = (0U == hdr.body_len_);
            lan_ = (hdr.first_byte_ >> 6) & 3;
            ltx_ = (hdr.first_byte_ >> 5) & 1;
            lrx_ = (hdr.first_byte_ >> 4) & 1;
            oan_ = (hdr.first_byte_ >> 2) & 3;
            otx_ = (hdr.first_byte_ >> 1) & 1;
            orx_ = (hdr.first_byte_ >> 0) & 1;
            plain_tx_ = (hdr.nibble_ >> 3) & 1;
            plain_rx_ = (hdr.nibble_ >> 2) & 1;
            delay_prot_ = (hdr.nibble_ >> 0) & 1;
            
            if (!empty_) {
                memcpy(lmi_, &data[4] , 12);
                des32( &data[16], lmn_);
                des32( &data[20], lpn_);

                memcpy(omi_, &data[24] , 12);
                des32( &data[36], omn_);
                des32( &data[40], opn_);
            }
        }
    }
    virtual uint32_t getSize(void) const { return present_*(4 + (!empty_)*40); }
    void reset(void) {
        new (this) SAKUse();
    }
};

struct DistSAK : public ILayer {
    bool present_       = true;
    bool empty_         = false;
    bool header_        = true;
    
    uint32_t dan_       = 2U;
    uint32_t conf_off_  = 1U;
    uint32_t keynum_    = 1U;
    uint64_t cipher_    = MKA_CS_ID_GCM_AES_128;
    uint8_t  wrap_[40]  = {6, 5, 4, 3, 2, 1, 6, 3, 6, 1, 2, 4, 6, 12, 5, 1, 5, 4, 4, 4, 4, 9,
                8, 3, 1, 1, 6, 2, 8, 4, 5, 2, 1, 89, 6, 22,45,81,95, 4 };
    int32_t  invalid_sz_ = -1;

    void serialise(uint8_t* where) const {
        if (!present_) return;
        MkParameter hdr(4, (dan_ << 6) + (conf_off_ << 4), 0, 
                    (invalid_sz_ >= 0) ? invalid_sz_ : getSize() - 4);
        hdr.serialise(where);
        if (getSize() == 32) {
            ser32(&where[4], keynum_);
            memcpy(&where[8], wrap_, 24);
        }
        if (getSize() >= 40) {
            ser32(&where[4], keynum_);
            ser64(&where[8], cipher_);
            memcpy(&where[16], wrap_, getSize() - 16);
        }
    }
    void deserialise(uint8_t const* data) {
        present_ = (4 == *data);
        invalid_sz_ = -1;
        if (!present_) {
            empty_ = false;
            header_ = false;
            dan_ = 0U;
            conf_off_ = 0U;
            keynum_ = 0U;
            cipher_ = 0U;
            memset(wrap_, 0, sizeof(wrap_));
        }
        else {
            MkParameter hdr(data);
            dan_ = (hdr.first_byte_ >> 6U) & 3U;
            conf_off_ = (hdr.first_byte_ >> 4U) & 3U;
            if ((empty_ = (0 == hdr.body_len_))) {
                header_ = false;
                keynum_ = 0U;
                cipher_ = MKA_CS_NULL;
            }
            else if ((header_ = (28 < hdr.body_len_))) {
                des32(&data[4], keynum_);
                des64(&data[8], cipher_);
                memcpy(wrap_, &data[16],
                    ((MKA_CS_ID_GCM_AES_256 == cipher_) || (MKA_CS_ID_GCM_AES_XPN_256 == cipher_)) ? 40 : 24);
            }
            else {
                des32(&data[4], keynum_);
                memcpy(wrap_, &data[8], 24);
                cipher_ = MKA_CS_ID_GCM_AES_128; // implicit default cipher suite
            }
        }
    }
    
    virtual uint32_t getSize(void) const {
        if (!present_)  return 0;
        if (invalid_sz_ >= 0) return (invalid_sz_+3)&(~3);
        if (empty_)     return 4;
        if (!header_)   return 4+28;
        if ((MKA_CS_ID_GCM_AES_256 == cipher_) || (MKA_CS_ID_GCM_AES_XPN_256 == cipher_))
                        return 4 + 52;
        else            return 4 + 36;
    }
    void reset(void) {
        new (this) DistSAK();
    }
};

struct XPN : public ILayer {
    bool present_       = false;
    bool empty_         = false;

    uint8_t     suspension = 0U;
    uint32_t    l_hpn   = 0U;
    uint32_t    o_hpn   = 0U;

    int32_t     invalid_sz_ = -1;

    void serialise(uint8_t* where) const {
        if (!present_) return;
        MkParameter hdr(8, suspension,  0U,
                    (invalid_sz_ >= 0) ? invalid_sz_ : (empty_ ? 0U : (getSize() - 4)));
        hdr.serialise(where);
        if (!empty_) {
            ser32(&where[4], l_hpn);
            ser32(&where[8], o_hpn);
        }
    }
    void deserialise(uint8_t const* data) {
        present_ = (8 == *data);
        invalid_sz_ = -1;
        if (!present_) {
            suspension = 0U;
            l_hpn = 0U;
            o_hpn = 0U;
        }
        else {
            invalid_sz_ = -1;
            MkParameter hdr(data);
            empty_ = (0U == hdr.body_len_);
            suspension = hdr.first_byte_;
            
            if (!empty_) {
                des32( &data[4],  l_hpn);
                des32( &data[8],  o_hpn);
            }
        }
    }
    virtual uint32_t getSize(void) const { return present_*(4 + (!empty_)*8); }
    void reset(void) {
        new (this) XPN();
    }
};

struct Announcement : public ILayer {
    bool present_       = false;
    bool empty_         = false;

    uint8_t     content_[256] = {
            0xe0, 0x14,
                    0x00, 0x02,     0x00, 0x80, 0xc2, 0x00, 0x01, 0x00, 0x00, 0x02,
                    0x00, 0x02,     0x00, 0x80, 0xc2, 0x00, 0x01, 0x00, 0x00, 0x01
        };
    uint32_t    content_len_ = 24U;

    int32_t     invalid_sz_ = -1;

    void resetCiphers(void) {
        content_[0] = 0xe0;
        content_[1] = 0x00;
        content_len_ = 2U;
    }
    void addCipher(t_MKA_macsec_cap cap, uint64_t cipher) {
        uint8_t ptr = 2U + content_[1];
        content_[ptr++] = 0U;
        content_[ptr++] = (uint8_t)cap;
        content_[ptr++] = cipher >> 56;
        content_[ptr++] = cipher >> 48;
        content_[ptr++] = cipher >> 40;
        content_[ptr++] = cipher >> 32;
        content_[ptr++] = cipher >> 24;
        content_[ptr++] = cipher >> 16;
        content_[ptr++] = cipher >>  8;
        content_[ptr++] = cipher >>  0;
        content_[1]  += 10U;
        content_len_ += 10U;
    }

    void serialise(uint8_t* where) const {
        if (!present_) return;
        MkParameter hdr(7, 0U,  0U,
                    (invalid_sz_ >= 0) ? invalid_sz_ : (empty_ ? 0U : content_len_));
        hdr.serialise(where);
        if (!empty_) {
            memcpy(&where[4], content_, content_len_);
        }
    }
    void deserialise(uint8_t const* data) {
        present_ = (7 == *data);
        invalid_sz_ = -1;
        if (!present_) {
            empty_ = false;
            content_len_ = 0U;
        }
        else {
            MkParameter hdr(data);
            content_len_ = hdr.body_len_;
            empty_ = (0U == content_len_);
            memcpy(content_, &data[4], content_len_);
        }
    }
    virtual uint32_t getSize(void) const { return present_*(4 + (!empty_)*((3 + content_len_)&0xFFFFFFFC)); }
    void reset(void) {
        new (this) Announcement();
    }
};

struct ICV : public ILayer {
    bool present_       = true;
    bool indication_    = true;
    uint8_t icv_[16U] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
    
    void serialise(uint8_t* where) const {
        if (!present_) return;
        if (indication_) {
            MkParameter hdr(255U, 0U, 0U, 16U);
            hdr.serialise(where);
            where+=4U;
        }
        memcpy(where, icv_, 16);
    }
    void deserialise(uint8_t const* data) {
        present_ = true;
        MkParameter hdr(data);
        indication_ = ((255U == hdr.type_) && (16U == hdr.body_len_)); // meh, it's a UT
        data += 4U * indication_;
        memcpy(icv_, data, 16U);
    }
    virtual uint32_t getSize(void) const { return present_*(indication_ ? 20U : 16U); }
    void reset(void) {
        new (this) ICV();
    }
};



struct PCAP {
    uint8_t *buffer         = nullptr;
    uint32_t ptr            = 0;
    uint32_t time_seg       = 0;
    uint32_t time_useg      = 0;
    uint32_t allocated      = 0;

    PCAP(void)
    {
        allocated = 1024;
        buffer = (uint8_t*)malloc(allocated);
        flush();
    }

    void flush(void)
    {
        ILayer::ser32(&buffer[ 0], 0xA1B2C3D4);
        ILayer::ser16(&buffer[ 4], 2);
        ILayer::ser16(&buffer[ 6], 4);
        ILayer::ser32(&buffer[ 8], 0);
        ILayer::ser32(&buffer[12], 0);
        ILayer::ser32(&buffer[16], 2000);
        ILayer::ser32(&buffer[20], 1);
        ptr = 24;

        time_seg  = 0;
        time_useg = 0;
    }

    ~PCAP(void) { free(buffer); }

    void append_frame(uint8_t const*frame, uint32_t size, uint32_t time_delta=100000U)
    {
        while((ptr+16+size) > allocated) {
            allocated *= 2;
            buffer = (uint8_t*)realloc(buffer, allocated);
        }
        ILayer::ser32(&buffer[ptr+ 0], time_seg);
        ILayer::ser32(&buffer[ptr+ 4], time_useg);
        ILayer::ser32(&buffer[ptr+ 8], size);
        ILayer::ser32(&buffer[ptr+12], size);
        memcpy(&buffer[ptr+16], frame, size);
        ptr += 16 + size;

        time_useg += time_delta;
        time_seg += time_useg / 1000000;
        time_useg %= 1000000;
    }

    void write(char const* filename) {
        FILE* f = fopen(filename, "wb");
        fwrite(buffer, ptr, 1, f);
        fclose(f);
    }
};

struct KayTestBase : public ::testing::Test {
    CMocks mocks;
    uint8_t frame[MKA_EAPOL_MAX_SIZE];
    uint32_t frame_size;
    t_mka_kay* ctx;
    t_mka_participant* participant;
    t_mka_peer* peer;

    t_MKA_global_config test_global_active_config = {
        .hello_time = 2000U,
        .bounded_hello_time = 500U,
        .life_time = 6000U,
        .sak_retire_time = 3000U,
        .hello_rampup = { 100U, 200U, 400U, 800U, 800U },
        .hello_rampup_number = 5U,
        .transmit_empty_dist_sak = true,
        .transmit_empty_sak_use = true,
        .transmit_null_xpn = true,
        .secy_polling_ms = 5U
    };

    t_MKA_bus_config test_buses_active_config = {
        .enable = true,
        .port_capabilities = {0},
        .port_name = "dummy",
        .port_number = 0,
        .controlled_port_name = "dummy",
        .kay = {
            .enable = true,
            .actor_priority = 128,
            .actor_role = MKA_ROLE_AUTO,
            .macsec_capable = MKA_MACSEC_INT_CONF_0,
            .macsec_desired = true,
            .replay_protect = true,
            .replay_protect_wnd = 1000U,
            .delay_protect = true,
            .pcpt_activation = MKA_ACTIVATE_ONOPERUP
        },
        .logon_nid = {
            .unauth_allowed = MKA_UNAUTH_IMMEDIATE,
            .unsecure_allowed = MKA_UNSECURE_IMMEDIATE
        },
        .logon_process = {
            .logon = false
        },
        .impl = {
            .phy_driver = { NULL },
            .key_mng = { NULL },
            .cipher_preference = {
                /* MKA_CS_ID_GCM_AES_XPN_256, */
                MKA_CS_ID_GCM_AES_128,
                /* MKA_CS_ID_GCM_AES_XPN_128, */
                MKA_CS_INVALID,
                /* MKA_CS_NULL */
                MKA_CS_INVALID,
                MKA_CS_INVALID,
                MKA_CS_INVALID
            },
            .conf_offset_preference = MKA_CONFIDENTIALITY_OFFSET_0,
            .mode = MKA_MACSEC_SOFTWARE,
            .mc_uart = NULL,
            .phy_settings = { 0 },
            .intf_mode = MKA_INTF_MODE_STATIC,
        }
    };

    static constexpr uint32_t M_NONE    = 0U;
    static constexpr uint32_t M_PPEERS  = 1U;
    static constexpr uint32_t M_LPEERS  = 2U;
    static constexpr uint32_t M_SAKUSE  = 4U;
    static constexpr uint32_t M_DISTSAK = 8U;
    static constexpr uint32_t M_ANN     = 16U;
    static constexpr uint32_t M_XPN     = 32U;

    PCAP pcap;

    t_MKA_ckn ckn = { "ab", 2U };
    t_MKA_key cak = { {0, 1, 2}, 16U };
    t_MKA_key kek = { {0, 2, 2}, 16U };
    t_MKA_key ick = { {0, 3, 2}, 16U };
    t_MKA_key sak = { {3, 0, 2}, 16U };

    uint8_t local_mac[6] = {0x00, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t local_mi[12] = {9, 12, 12, 12, 12, 12, 33, 44, 55, 66, 11, 12};
    uint8_t ks_nonce[32] = {1,2,3,4,5,6,7,8,9,10};

    const t_MKA_ki null_ki = {{0}};

    t_MKA_receive_sc    rxsc = {0};
    t_MKA_transmit_sc   txsc = {0};
    t_MKA_receive_sa    rxsa = {.in_use=true, .ssci=0, .next_pn=55, .lowest_pn=66};
    t_MKA_transmit_sa   txsa = {.in_use=true, .confidentiality=MKA_CONFIDENTIALITY_NONE, .ssci=0, .next_pn=77};

    uint32_t rx_mn = 0x10AU;

    EthHdr              ethhdr;
    EAPOLHdr            eapol;
    BPSHdr              bps;
    PotentialPeerList   ppeers;
    LivePeerList        lpeers;
    SAKUse              sakuse;
    DistSAK             distsak;
    Announcement        ann;
    XPN                 xpn;
    ICV                 icv;

    uint32_t force_mkpdu_len = 0;
    uint32_t last_frame = 555U;

    KayTestBase(void) :
            ctx(&mka_kay[0]),
            participant(&ctx->participant),
            peer(&participant->peer)
    {
        MKA_active_buses_config = &test_buses_active_config;
    }

    ~KayTestBase(void)
    {
        MKA_active_buses_config = nullptr;
    }

    void serialise(ILayer** layout = nullptr) {
        bps.mn_ = rx_mn;
        if (nullptr == layout) {
            layout = getLayout();
        }
        for(uint8_t i=0U; i<2U; ++i) {
            frame_size=0U;
            for(ILayer **layer = layout; *layer; ++layer) {
                (*layer)->serialise(&frame[frame_size]);
                frame_size += (*layer)->getSize();
            }

            if (force_mkpdu_len > 0) {
                eapol.body_len_ = force_mkpdu_len;
            }
            else {
                eapol.body_len_ = frame_size - ethhdr.getSize() - eapol.getSize();
            }
        }
    }

    virtual void SetUp(bool const doInit=true) {
        memset(mka_kay, 0, sizeof(mka_kay));
        MKA_active_global_config = &test_global_active_config;
        mka_tick_time_ms = 555U;

        test_global_active_config.transmit_empty_dist_sak = true;
        test_global_active_config.transmit_empty_sak_use = true;
        test_global_active_config.transmit_null_xpn = true;
        
        if (doInit) {
            EXPECT_CALL(mocks, MKA_l2_init(0, 0x888E)) .WillOnce(Return(MKA_OK));
            EXPECT_CALL(mocks, MKA_l2_getLocalAddr(0, _)) .WillRepeatedly(DoAll(MemcpyToArg<1>((void*)local_mac, 6), Return(MKA_OK)));
            MKA_KAY_Init(0U);
        }

        EXPECT_CALL(mocks, MKA_SECY_TransmitSA_UpdateNextPN(0, _))
            .WillRepeatedly(Invoke([](t_MKA_bus bus, t_MKA_transmit_sa*sa) {
                return MKA_OK;
            }));
    }

    virtual void TearDown(void) {
        struct stat current_stat;
        bool chdir_to_build = (0 == ::stat("build", &current_stat));

        if (chdir_to_build)
            chdir("build");

        char filename[512];
        sprintf(filename, "packet_SUITE_%s_TEST_%s.pcap",
            ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name(),
            ::testing::UnitTest::GetInstance()->current_test_info()->name());
        mkdir("pcaps", 0755);
        int fptr = sprintf(filename, "pcaps/%s",
            ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name());
        for(int z = 7; z < fptr; ++z) {
            if (filename[z] == '/') {
                filename[z] = '-';
            }
        }
        mkdir(filename, 0755);
        sprintf(filename, "pcaps/%s/%s.pcap",
            ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name(),
            ::testing::UnitTest::GetInstance()->current_test_info()->name());
        for(int z = 7; filename[z]; ++z) {
            if (z == fptr) continue;
            if (filename[z] == '/') {
                filename[z] = '-';
            }
        }
        pcap.write(filename);

        if (chdir_to_build)
            chdir("..");
    }

    virtual ILayer** getLayout(void) = 0;

    void FeedFrame(bool do_serialise = true, bool handle_icv = false) {
        if (do_serialise) {
            serialise();
        }

        pcap.append_frame(frame, frame_size, 1000*(mka_tick_time_ms - last_frame));
        last_frame = mka_tick_time_ms;
        EXPECT_CALL(mocks, MKA_l2_receive(0, _, MemoryWith<uint32_t>({MKA_EAPOL_MAX_SIZE})))
            .WillOnce(DoAll(MemcpyToArg<1>((void*)frame, MKA_EAPOL_MAX_SIZE),
                            SetArgPointee<2U>(frame_size),
                            Return(MKA_OK)));

        if (handle_icv) {
            EXPECT_CALL(mocks, MKA_ComputeICV(
                    /* alg. ag  */  MKA_ALGORITHM_AGILITY,
                    /* ICK      */  &mka_kay[0].participant.ick,
                    /* message  */  MemoryWith<uint8_t>(frame, 20U),
                    /* length   */  _,
                    /* ICV      */  _
                )) .WillOnce(DoAll(
                        MemcpyToArg<4>(icv.icv_, MKA_ICV_LENGTH),
                        Return(true)
                ));
        }

        MKA_KAY_MainFunction(0);
        //mka_receive_from_l2(0U);
        ++rx_mn; // Increase message number
    }

    void layersReset(void)
    {
        ethhdr.reset();
        eapol.reset();
        bps.reset();
        ppeers.reset();
        lpeers.reset();
        sakuse.reset();
        distsak.reset();
        ann.reset();
        xpn.reset();
        icv.reset();
    }

    void ExpectPresentLayers(uint32_t mask) {
        EXPECT_THAT(ppeers.present_,    (bool)(M_PPEERS  & mask));
        EXPECT_THAT(lpeers.present_,    (bool)(M_LPEERS  & mask));
        EXPECT_THAT(sakuse.present_,    (bool)(M_SAKUSE  & mask));
        EXPECT_THAT(distsak.present_,   (bool)(M_DISTSAK & mask));
        EXPECT_THAT(ann.present_,       (bool)(M_ANN     & mask));
        EXPECT_THAT(xpn.present_,       (bool)(M_XPN     & mask));
    }
    void SetPresentLayers(uint32_t mask) {
        ppeers.present_   = (bool)(M_PPEERS  & mask);
        lpeers.present_   = (bool)(M_LPEERS  & mask);
        sakuse.present_   = (bool)(M_SAKUSE  & mask);
        distsak.present_  = (bool)(M_DISTSAK & mask);
        ann.present_      = (bool)(M_ANN     & mask);
        xpn.present_      = (bool)(M_XPN     & mask);
    }

    void ExpectNoTransmission(void)
    {
        EXPECT_CALL(mocks, MKA_l2_receive(0, _, _)) .WillOnce(Return(MKA_NOT_OK));
        EXPECT_CALL(mocks, MKA_l2_getLocalAddr(0, _)) .Times(0);
        EXPECT_CALL(mocks, MKA_l2_transmit(_,_,_)) .Times(0);
        MKA_KAY_MainFunction(0);
    }

    void HandlePreTransmission(bool handle_icv=true, bool handle_rx=true)
    {
        if (handle_icv) {
            EXPECT_CALL(mocks, MKA_ComputeICV(
                    /* alg. ag  */  MKA_ALGORITHM_AGILITY,
                    /* ICK      */  &mka_kay[0].participant.ick,
                    /* message  */  _,
                    /* length   */  _,
                    /* ICV      */  _
                )) .WillOnce(DoAll(
                        MemcpyToArg<4>(icv.icv_, MKA_ICV_LENGTH),
                        Return(true)
                )) .RetiresOnSaturation();
        }

        if (handle_rx) {
            EXPECT_CALL(mocks, MKA_l2_receive(0, _, _))
                .WillOnce(Return(MKA_NOT_OK));
        }

        EXPECT_CALL(mocks, MKA_l2_getLocalAddr(0, _))
            .WillOnce(DoAll(MemcpyToArg<1>((void*)local_mac, 6), Return(MKA_OK)));

        auto HandlePostTransmission_ = [this] {
            ILayer** layout = getLayout();

            ppeers.present_ = false;
            lpeers.present_ = false;
            sakuse.present_ = false;
            distsak.present_ = false;
            ann.present_    = false;
            xpn.present_    = false;

            uint32_t idx = 0;
            for(int i=0; (layout[i]) && ((frame_size - idx) > 16); ++i) {
                layout[i]->deserialise(&frame[idx]);
                idx += layout[i]->getSize();
            }

            ASSERT_THAT(frame_size-idx, Ge(16)) << "Expected a frame remainder of 16 bytes for ICV";
            icv.deserialise(&frame[idx]);
        };

        EXPECT_CALL(mocks, MKA_l2_transmit(
                /* bus      */ 0,
                /* packet   */ _,
                /* len      */ _
            )) .WillOnce(Invoke([this, HandlePostTransmission_](t_MKA_bus bus, uint8_t const*packet, uint32_t len) -> t_MKA_result {
                memcpy(this->frame, packet, MKA_EAPOL_MAX_SIZE);
                this->frame_size = len;
                this->pcap.append_frame(packet, len, 1000*(mka_tick_time_ms - last_frame));
                this->last_frame = mka_tick_time_ms;
                HandlePostTransmission_();
                return MKA_OK;

            })) .RetiresOnSaturation();
    }

    void HandleTransmission(bool force_participate=true, bool handle_icv=true)
    {
        HandlePreTransmission(handle_icv, true);

        if (force_participate) {
            MKA_KAY_Participate(0, true); // this shall force frame transmission
        }
        MKA_KAY_MainFunction(0);
    }

    void MKA_KAY_MainFunction(t_MKA_bus bus)
    {
        MKA_KAY_MainFunctionReception(bus);
        MKA_KAY_MainFunctionTimers(bus);
        MKA_KAY_MainFunctionTransmission(bus);
    }
};



#endif
