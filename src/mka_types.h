/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_types.h
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
 * @file        mka_types.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA types abstraction
 *
 * @{
 */

#ifndef MKA_TYPES_H_
#define MKA_TYPES_H_

/*******************        Includes        *************************/
#include <stdint.h>     // Machine types
#include <stdbool.h>    // bool
#include <string.h>     // memcpy/memset/..
#ifndef MKA_ATOMIC_OVERRIDE
# include <signal.h>    // ANSI C sig_atomic_t
#endif

//lint -save
//lint -e9026 [MISRA 2012 Directive 4.9, advisory] Function-like macros for os-abstraction

// MISRA C++ justifications
//lint -e1923 [MISRA C++ Rule 16-2-2] C requires macros instead of constexpr
//lint -e1960 [MISRA C++ Rule 16-0-4] Function-like macros for os-abstraction
//lint -e761 no-misra rule, false positive

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/
// Logging levels
#define MKA_LOGLEVEL_DISABLED       0U
#define MKA_LOGLEVEL_ERROR          1U
#define MKA_LOGLEVEL_WARNING        2U
#define MKA_LOGLEVEL_INFO           3U
#define MKA_LOGLEVEL_DEBUG          4U

// On/off options
#define MKA_ON                      1U
#define MKA_OFF                     0U

// OS+IP stack identifier
#define MKA_OS_FREERTOS_LWIP        0U
#define MKA_OS_LINUX                1U
#define MKA_OS_AUTOSAR              2U
#define MKA_OS_MARVELL_SDK          3U

// Identifier of the different layer 2 implementations
#define MKA_LAYER2_LWIP             0U

// Empty action for configuration file
#define MKA_NO_ACTION               (void)0

// Special bus identifier
#define MKA_BUS_NONE                255U

// Constants
#define MKA_L2_ADDR_SIZE            6U      // Ethernet MAC size
#define MKA_L2_PROTO_EAPOL          0x888EU // Ethernet Proto
#define MKA_MI_LENGTH               12U // Member identifier length
#define MKA_ICV_LENGTH              16U // 128 bit
#define MKA_KEY_MAX                 32U // 256 bits -> 32 octets
#define MKA_KEY_MIN                 16U // 128 bits -> 16 octets
#define MKA_KEY_WRAPPED_MAX         40U // 320 bits -> 40 octets
#define MKA_KEY_128BIT              16U
#define MKA_KEY_256BIT              32U
#define MKA_KEY_128BIT_WRAPPED      24U
#define MKA_KEY_256BIT_WRAPPED      40U
#define MKA_CKN_MIN                 1U  // IEEE 802.11X 9.3.1
#define MKA_CKN_MAX                 32U // IEEE 802.11X 9.3.1

#define MKA_EAPOL_VERSION           3U
#define MKA_EAPOL_MAX_SIZE          512U
#define MKA_EAPOL_TYPE_MKAPDU       5U
#define MKA_MKPDU_MIN_LENGTH        32U

// Cipher suites
#define MKA_CS_ID_LEN               8
#define MKA_CS_NULL                 0xFFFFFFFFFFFFFFFFULL
#define MKA_CS_ID_GCM_AES_128       0x0080C20001000001ULL
#define MKA_CS_ID_GCM_AES_256       0x0080C20001000002ULL
#define MKA_CS_ID_GCM_AES_XPN_128   0x0080C20001000003ULL
#define MKA_CS_ID_GCM_AES_XPN_256   0x0080C20001000004ULL
#define MKA_CS_INVALID              0x0000000000000000ULL
//#define MKA_CS_NAME_GCM_AES_128     "GCM-AES-128"
//#define MKA_CS_NAME_GCM_AES_256     "GCM-AES-256"

/// IEEE 802.1x-2020 see table 9-1
#define MKA_ALGORITHM_AGILITY       0x0080C201U

// Endianness
#define MKA_BIG_ENDIAN              1U
#define MKA_LITTLE_ENDIAN           2U


#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_realloc
#define os_realloc(p, s) realloc((p), (s))
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif
#ifndef os_strdup
#define os_strdup(s) strdup(s)
#endif

#ifndef os_memcpy
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#endif
#ifndef os_memmove
#define os_memmove(d, s, n) memmove((d), (s), (n))
#endif
#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif

#if defined(PCLINT) // Static analyser
# define MKA_PACK_STRUCT        __attribute__((packed))
# define MKA_ENDIANNESS        MKA_BIG_ENDIAN

#elif defined(__GNUC__) // GCC
# define MKA_PACK_STRUCT        __attribute__((packed))
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define MKA_ENDIANNESS        MKA_LITTLE_ENDIAN
# else
#  define MKA_ENDIANNESS        MKA_BIG_ENDIAN
# endif

#else
# error "Adaptation for compiler / machine missing"

#endif

#define SWAP_16B(x) \
    ((((x) << 8U) & 0xFF00U) | (((x) >> 8U) & 0x00FFU))

#define SWAP_32B(x) \
    ((((x) << 24U) & 0xFF000000U) | (((x) << 8U) & 0x00FF0000U)  | \
     (((x) >> 24U) & 0x000000FFU) | (((x) >> 8U) & 0x0000FF00U))

#define SWAP_64B(x) \
    ((SWAP_32B((x) & 0xFFFFFFFFULL) << 32U) | (SWAP_32B((x) >> 32U) & 0xFFFFFFFFULL))

#if MKA_ENDIANNESS == MKA_BIG_ENDIAN
/// Host to Network order converter (short - 16 bit)
# define MKA_HTONS(x)       (x)
/// Network to Host order converter (short - 16 bit)
# define MKA_NTOHS(x)       (x)
/// Host to Network order converter (long - 32 bit)
# define MKA_HTONL(x)       (x)
/// Network to Host order converter (long - 32 bit)
# define MKA_NTOHL(x)       (x)
/// Host to Network order converter (quad - 64 bit)
# define MKA_HTONQ(x)       (x)
/// Network to Host order converter (quad - 64 bit)
# define MKA_NTOHQ(x)       (x)

#else // Little endian
/// Host to Network order converter (short - 16 bit)
# define MKA_HTONS(x)       SWAP_16B(x)
/// Network to Host order converter (short - 16 bit)
# define MKA_NTOHS(x)       SWAP_16B(x)
/// Host to Network order converter (long - 32 bit)
# define MKA_HTONL(x)       SWAP_32B(x)
/// Network to Host order converter (long - 32 bit)
# define MKA_NTOHL(x)       SWAP_32B(x)
/// Host to Network order converter (quad - 64 bit)
# define MKA_HTONQ(x)       SWAP_64B(x)
/// Network to Host order converter (quad - 64 bit)
# define MKA_NTOHQ(x)       SWAP_64B(x)
#endif

#define MKA_NBTOQ(x)        ( \
    (((uint64_t)(x)[0U]) << 56U) | \
    (((uint64_t)(x)[1U]) << 48U) | \
    (((uint64_t)(x)[2U]) << 40U) | \
    (((uint64_t)(x)[3U]) << 32U) | \
    (((uint64_t)(x)[4U]) << 24U) | \
    (((uint64_t)(x)[5U]) << 16U) | \
    (((uint64_t)(x)[6U]) <<  8U) | \
    (((uint64_t)(x)[7U])       ) )

#ifdef UNIT_TEST
# define MKA_PRIVATE        /* empty */
#else
# define MKA_PRIVATE        static
#endif

#ifdef UNIT_TEST
# define MKA_CONST          /* empty */
#else
# define MKA_CONST          const
#endif

#define MKA_MIN(a, b)   ( ((a) < (b)) ? (a) : (b) )
#define MKA_MAX(a, b)   ( ((a) < (b)) ? (b) : (a) )

#define MKA_ATOMIC_TRUE     1L
#define MKA_ATOMIC_FALSE    0L

/*******************        Types             ***********************/
/* Types used in crypto abstraction */
// TODO: delete at some point?
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

/* MISRA rule 6.1 compliance for bitfields */
typedef unsigned int    uint_t;
typedef signed int      sint_t;

#ifdef MKA_ATOMIC_OVERRIDE
typedef volatile MKA_ATOMIC_OVERRIDE     int_atomic_t;
#else
typedef volatile sig_atomic_t            int_atomic_t;
#endif

typedef uint8_t t_MKA_bus;
typedef char const* t_MKA_l2_reference;

/// Packet number
typedef uint64_t t_MKA_pn;

/// SSCI
typedef uint32_t t_MKA_ssci;

/// Cipher suite
typedef uint64_t t_MKA_ciphsuite;

typedef enum {
    MKA_EVENT_INIT,
    MKA_EVENT_PORT_VALID,
    MKA_EVENT_PORT_NOT_VALID,
    MKA_EVENT_LINKUP
} t_MKA_event;

typedef enum {
    MKA_OK,
    MKA_NOT_OK
} t_MKA_result;

typedef enum {
    MKA_PENDING = 1,
    MKA_UNAUTHENTICATED = 2,
    MKA_AUTHENTICATED = 3,
    MKA_SECURED = 4,
    MKA_FAILED = 5
} t_MKA_connect_mode;

/**
 * struct ieee802_1x_mka_ki - Key Identifier (KI)
 * @mi: Key Server's Member Identifier
 * @kn: Key Number, assigned by the Key Server
 * IEEE 802.1X-2020 9.8 SAK generation, distribution, and selection
 */
typedef struct {
    uint8_t             mi[MKA_MI_LENGTH];
    uint32_t            kn;
} t_MKA_ki;

/// Connectivity Association Key - CAK
typedef struct {
    // TODO add fields/identifiers so that we can operate with it even
    // when installed inside a crypto module
    uint8_t             key[MKA_KEY_MAX];
    uint8_t             length;
} t_MKA_key;

/// Connectivity Association Key Name - CKN
typedef struct {
    uint8_t             name[MKA_CKN_MAX]; // 1 to 32 octets
    uint8_t             length;
} t_MKA_ckn;

/* IEEE Std 802.1X-2020 - Table 11-6 - Confidentiality Offset */
typedef enum {
	MKA_CONFIDENTIALITY_NONE      = 0,
	MKA_CONFIDENTIALITY_OFFSET_0  = 1,
	MKA_CONFIDENTIALITY_OFFSET_30 = 2,
	MKA_CONFIDENTIALITY_OFFSET_50 = 3
} t_MKA_confidentiality_offset;

/* IEEE Std 802.1X-2020 - Table 11-6 - MACSEC capability */
typedef enum {
    MKA_MACSEC_NOT_IMPLEMENTED = 0,
    MKA_MACSEC_INTEGRITY = 1,
    MKA_MACSEC_INT_CONF_0 = 2,
    MKA_MACSEC_INT_CONF_0_30_50 = 3
} t_MKA_macsec_cap;

/// MKA Validation
typedef enum {
    MKA_VALIDATE_NULL,
	MKA_VALIDATE_DISABLED,
	MKA_VALIDATE_CHECKED,
	MKA_VALIDATE_STRICT
} t_MKA_validate_frames;

/* IEEE Std 802.1X 2020 Chapter 9.16 */
typedef enum {
    MKA_ACTIVATE_DISABLED   = 0,
    MKA_ACTIVATE_ONOPERUP   = 1,
    MKA_ACTIVATE_ALWAYS     = 2
} t_MKA_activate;

typedef enum {
    MKA_UNAUTH_NEVER,
    MKA_UNAUTH_IMMEDIATE,           // default
    MKA_UNAUTH_ON_AUTH_FAIL
} t_MKA_unauth_allow;

typedef enum {
    MKA_UNSECURE_NEVER,
    MKA_UNSECURE_IMMEDIATE,         // default
    MKA_UNSECURE_ON_MKA_FAIL,
    MKA_UNSECURE_PER_MKA_SERVER
} t_MKA_unsec_allow;

typedef enum {
    MKA_ROLE_AUTO,
    MKA_ROLE_FORCE_KEY_SERVER,
    MKA_ROLE_FORCE_KEY_CLIENT
} t_MKA_role;


typedef enum {
    MKA_INTF_MODE_STATIC,
    MKA_INTF_MODE_DYNAMIC
} t_MKA_intf_mode;

typedef enum {
    MKA_STATUS_MACSEC_RUNNING = 0,
    MKA_STATUS_WAITING_PEER_LINK = 1,
    MKA_STATUS_WAITING_PEER = 2,
    MKA_STATUS_IN_PROGRESS = 3,
    MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER = 6,
    MKA_STATUS_AUTH_FAIL_CERTIFICATE = 7,
    MKA_STATUS_UNDEFINED = 0xFF
} t_MKA_bus_status;

/// Ethernet header
typedef struct {
    uint8_t dst[MKA_L2_ADDR_SIZE];
    uint8_t src[MKA_L2_ADDR_SIZE];
    uint16_t type;
} MKA_PACK_STRUCT t_MKA_l2_ether_header;

/// Secure channel identifier, (802.1AE)
typedef struct {
    uint8_t addr[MKA_L2_ADDR_SIZE];
    uint16_t port;
} MKA_PACK_STRUCT t_MKA_sci;

/// IEEE 802.1AE Figure 10-5, Verification
typedef struct {
    uint64_t            in_pkts_untagged;
    uint64_t            in_pkts_no_tag;
    uint64_t            in_pkts_bad_tag;
    uint64_t            in_pkts_no_sa;
    uint64_t            in_pkts_no_sa_error;
    uint64_t            in_pkts_overrun;
    uint64_t            in_octets_validated;
    uint64_t            in_octets_decrypted;
} t_MKA_stats_receive_secy;

/// IEEE 802.1AE Figure 10-5, ReceiveSC
typedef struct {
    uint64_t            in_pkts_ok;
    uint64_t            in_pkts_unchecked;
    uint64_t            in_pkts_delayed; 
    uint64_t            in_pkts_late;
    uint64_t            in_pkts_invalid;
    uint64_t            in_pkts_not_valid;
} t_MKA_stats_receive_sc;

/// IEEE 802.1AE Figure 10-5, ReceiveSC
typedef struct {
    t_MKA_sci           sci;
    bool                receiving; // read only
    uint32_t            created_time; // read only
    uint32_t            started_time; // read only
    uint32_t            stopped_time; // read only

    t_MKA_stats_receive_sc *sc_stats;
    // relation to ReceiveSA "rxa", 0..3
} t_MKA_receive_sc;

/// IEEE 802.1AE Figure 10-5, ReceiveSA
typedef struct {
    bool                in_use; // read only
    t_MKA_ssci          ssci; // read only
    t_MKA_pn            next_pn; // read only
    t_MKA_pn            lowest_pn; // read only

    uint32_t            created_time; // read only
    uint32_t            started_time; // read only
    uint32_t            stopped_time; // read only

    // SecY private
    uint8_t             an;         // read only
    void*               data_key;
    bool                enable_receive;
} t_MKA_receive_sa;

/// IEEE 802.1AE Figure 10-5, Generation
typedef struct {
    uint64_t            out_pkts_untagged;
    uint64_t            out_pkts_too_long;
    uint64_t            out_octets_protected;
    uint64_t            out_octets_encrypted;
} t_MKA_stats_transmit_secy;

/// IEEE 802.1AE Figure 10-5, TransmitSC
typedef struct {
    uint64_t            out_pkts_protected;
    uint64_t            out_pkts_encrypted;
} t_MKA_stats_transmit_sc;

/// IEEE 802.1AE Figure 10-5, TransmitSC
typedef struct {
    t_MKA_sci           sci;
    bool                transmitting; // read only
    uint32_t            created_time; // read only
    uint32_t            started_time; // read only
    uint32_t            stopped_time; // read only

    t_MKA_stats_transmit_sc *sc_stats;
    // relation to TransmitSA "txa", 0..3
} t_MKA_transmit_sc;

/// IEEE 802.1AE Figure 10-5, TransmitSA
typedef struct {
    bool                in_use;
    t_MKA_confidentiality_offset confidentiality;
    t_MKA_ssci          ssci; // read only
    t_MKA_pn            next_pn;

    uint32_t            created_time; // read only
    uint32_t            started_time; // read only
    uint32_t            stopped_time; // read only

    uint8_t             an;         // read only
    void*               data_key;
    bool                enable_transmit; // read only
} t_MKA_transmit_sa;

/// SAK information
typedef struct {
    void*               secy_reference;

    t_MKA_pn            next_pn;
    t_MKA_confidentiality_offset
                        confidentiality_offset;
    uint8_t             association_number;

    uint64_t            cipher;

    uint32_t            creation;
    bool                transmits;
    bool                receives;

    t_MKA_ki            identifier;

    t_MKA_transmit_sa   *txsa;
    t_MKA_receive_sa    *rxsa;
} t_MKA_sak;

typedef struct {
    t_MKA_bus_status    status;
    t_MKA_sci           peer_sci; // includes peer's MAC and port
} t_MKA_bus_info;

/// Config interface between CP & SecY, IEEE 802.1X Figure 12-1
typedef struct {
    bool protect_frames;
    bool replay_protect;
    uint32_t replay_window;
    t_MKA_validate_frames validate_frames;
    uint64_t current_cipher_suite;
    t_MKA_confidentiality_offset confidentiality_offset;
    bool controlled_port_enabled;
} t_MKA_SECY_config;

/// PHY Driver dynamic functions
typedef struct {
    t_MKA_result(*UpdateSecY)(t_MKA_bus bus, t_MKA_SECY_config const * config, t_MKA_sci const * tx_sci);
    t_MKA_result(*InitRxSC)(t_MKA_bus bus, t_MKA_sci const * sci);
    t_MKA_result(*DeinitRxSC)(t_MKA_bus bus, t_MKA_sci const * sci);
    t_MKA_result(*AddTxSA)(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active);
    t_MKA_result(*UpdateTxSA)(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active);
    t_MKA_result(*DeleteTxSA)(t_MKA_bus bus, uint8_t an);
    t_MKA_result(*AddRxSA)(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active);
    t_MKA_result(*UpdateRxSA)(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active);
    t_MKA_result(*DeleteRxSA)(t_MKA_bus bus, uint8_t an);
    t_MKA_result(*GetTxSANextPN)(t_MKA_bus bus, uint8_t an, t_MKA_pn* next_pn);
    t_MKA_result(*GetMacSecStats)(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy, t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc);
} t_MKA_PhyDrv_config;

/// PHY driver bypass by L2 address
typedef struct {
    uint8_t address[6];                         ///< MAC address
    bool enable;                                ///< bypass enable
} t_MKA_PhyDrv_addr_bypass;

/// PHY driver static settings
typedef struct {
    bool                        vlan_bypass;     ///< TRUE: all protected except given VLAN's; FALSE: only given VLAN's are protected.
    uint16_t                    vlan[4];         ///< MACsec VLAN list (leave unused slots to Phy::VLAN_EMPTY).
    uint16_t                    proto_bypass[8]; ///< MACsec bypass ethertype list (leave unused slots to Phy::ETHTYPE_UNUSED).
    t_MKA_PhyDrv_addr_bypass    DA_bypass[8];    ///< MACsec bypass destination MAC address list (leave unused slots enable false).
    bool                        transmit_sci;    ///< MACsec transmit SCI in frames (SC bit on TCI field), in case multiple MACs should transmit over a single MACsec channel.
    uint16_t                    transmit_mtu;    ///< Transmit maximum transfer unit for the PHY to consider when adding Security Tag.
} t_MKA_PhyDrv_settings;

/// Key Management functions
typedef struct {
    t_MKA_result(*RetrieveCAKCKN)(t_MKA_bus bus, t_MKA_key * const cak, t_MKA_ckn * const ckn);
    t_MKA_result(*RetrieveKEK)(t_MKA_bus bus, t_MKA_key * const kek);
    t_MKA_result(*RetrieveICK)(t_MKA_bus bus, t_MKA_key * const ick);
} t_MKA_KeyMng;


/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/


#ifdef __cplusplus
}
#endif

#endif /* MKA_TYPES_H_ */

//lint -restore

/** @} */
