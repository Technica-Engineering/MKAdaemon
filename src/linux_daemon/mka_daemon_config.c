/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_daemon_config.c
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
 * @file        mka_daemon_config.c
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA configuration importer
 *
 * @{
 */

/*******************        Includes        *************************/
#include <yaml.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "mka_private.h"
#include "mka_phy_driver.h"

/*******************        Defines           ***********************/
#ifdef UNIT_TEST
#define FATAL(fmt, ...)     MKA_LOG_ERROR("MKAD fatal error loading configuration: " fmt, ## __VA_ARGS__)
#define STATIC              /* empty */
#else
#define FATAL(fmt, ...)        do { \
        MKA_LOG_ERROR("MKAD fatal error loading configuration: " fmt, ## __VA_ARGS__); \
        (void)fprintf(stderr, "MKAD fatal error loading configuration: " fmt "\r\n", ## __VA_ARGS__); \
    } while(0)
#define STATIC              static
#endif

#define FATAL_AT(pEvent, fmt, ...) \
        FATAL("line %li, " fmt, (1+(pEvent)->start_mark.line), ## __VA_ARGS__)

#define STR_EQUAL(a, b)     (0 == strcasecmp((char const*)(a), (char const*)(b)))

/*******************        Types             ***********************/
typedef enum {
    ETYPE_UINT32,
    ETYPE_UINT16,
    ETYPE_UINT8,
    ETYPE_BOOL,
    ETYPE_STRING,
    ETYPE_LOG_LEVEL,
    ETYPE_ROLE,
    ETYPE_REPLAY,
    ETYPE_HELLO_RAMPUP,
    ETYPE_HEX_LIST,
    ETYPE_MACSEC_MODE,
    ETYPE_CIPHERS,
    ETYPE_CAK,
    ETYPE_CKN,
    ETYPE_INTF_MODE,
    ETYPE_UNAUTH,
    ETYPE_UNSECURE,
    ETYPE_DRV_MACSEC_MODE,
    ETYPE_VLANBYP_LIST,
    ETYPE_PROTOBYP_LIST,
    ETYPE_MACBYP_LIST
} t_config_elem_type;

typedef struct {
    bool                    mandatory;
    char const*             name;
    t_config_elem_type      type;
    void*                   holder;
    uint32_t                uint_min;
    uint32_t                uint_max;
} t_config_elem;

typedef struct {
    t_config_elem_type      type;
    bool                    (*func)(yaml_parser_t *, yaml_event_t *, t_config_elem const*);
} t_type_handlers;

typedef struct {
    t_MKA_key               cak;
    t_MKA_ckn               ckn;
    t_MKA_key               kek;
    t_MKA_key               ick;
} t_bus_keys;

typedef bool (*t_list_elem_handler)(yaml_parser_t *, yaml_event_t *, t_config_elem const*, uint32_t idx, char const*);

/*******************        Variables         ***********************/
// Global configuration holders and default values
uint8_t     mka_active_log_level        = MKA_LOGLEVEL_WARNING;
uint8_t     mka_active_log_verbosity    = 1U;

// Per-bus configuration
STATIC t_MKA_config         mka_config = {0};
static t_bus_keys           keys[MKA_NUM_BUSES] = {0};
uint32_t                    mka_num_buses_configured = 0U;

char const* type2string[] = {
    "NONE",
    "STREAM_START",
    "STREAM_END",
    "DOCUMENT_START",
    "DOCUMENT_END",
    "ALIAS",
    "SCALAR",
    "SEQUENCE_START",
    "SEQUENCE_END",
    "MAPPING_START",
    "MAPPING_END",
};

static const t_config_elem root_elements[] = {
// mandatory    name                        type                variable                                                 min max
    { true,     "log_level",                ETYPE_LOG_LEVEL,    (void*)&mka_active_log_level,                            0U, 0U },
    { true,     "verbosity",                ETYPE_UINT8,        (void*)&mka_active_log_verbosity,                        0U, 3U },
    { true,     "hello_time",               ETYPE_UINT32,       (void*)&mka_config.global_config.hello_time,             0U, 100000U },
    { true,     "bounded_hello_time",       ETYPE_UINT32,       (void*)&mka_config.global_config.bounded_hello_time,     0U, 100000U },
    { true,     "life_time",                ETYPE_UINT32,       (void*)&mka_config.global_config.life_time,              0U, 100000U },
    { true,     "sak_retire_time",          ETYPE_UINT32,       (void*)&mka_config.global_config.sak_retire_time,        0U, 100000U },
    { false,    "hello_time_rampup",        ETYPE_HELLO_RAMPUP, NULL /* custom implementation */,                        0U, 100000U },
    { true,     "transmit_empty_dist_sak",  ETYPE_BOOL,         (void*)&mka_config.global_config.transmit_empty_dist_sak,0U, 1U },
    { true,     "transmit_empty_sak_use",   ETYPE_BOOL,         (void*)&mka_config.global_config.transmit_empty_sak_use, 0U, 1U },
    { true,     "transmit_null_xpn",        ETYPE_BOOL,         (void*)&mka_config.global_config.transmit_null_xpn,      0U, 1U },
    { true,     "secy_polling_ms",          ETYPE_UINT32,       (void*)&mka_config.global_config.secy_polling_ms,        0U, 1000U },
};

#define BUS_PARAM(x)    ((void*)&(mka_config.bus_config[0].x))
static const t_config_elem interface_elements[] = {
// mandatory    name                        type                    variable                            min max
    { true,     "macsec",                   ETYPE_MACSEC_MODE,      NULL /* Maps to multiple parameters */,     0U, 1U },
    { false,    "announcements",            ETYPE_BOOL,             BUS_PARAM(port_capabilities.announcements), 0U, 0U },
    { false,    "listener",                 ETYPE_BOOL,             BUS_PARAM(port_capabilities.listener),      0U, 0U },

    { true,     "protected_device",         ETYPE_STRING,           BUS_PARAM(controlled_port_name),            0U, 0U },
    { true,     "device",                   ETYPE_STRING,           BUS_PARAM(port_name),                       0U, 0U },

    { false,    "kay",                      ETYPE_BOOL,             BUS_PARAM(kay.enable),                      0U, 1U },
    { true,     "priority",                 ETYPE_UINT8,            BUS_PARAM(kay.actor_priority),              0U, 255U },
    { true,     "role",                     ETYPE_ROLE,             BUS_PARAM(kay.actor_role),                  0U, 255U },
    { false,    "replay_protect",           ETYPE_REPLAY,           BUS_PARAM(kay.replay_protect_wnd),          0U, 0xFFFFFFFFU },
    { true,     "delay_protect",            ETYPE_BOOL,             BUS_PARAM(kay.delay_protect),               0U, 1U },

    { false,    "unauth_allowed",           ETYPE_UNAUTH,           BUS_PARAM(logon_nid.unauth_allowed),        0U, 0U },
    { false,    "unsecure_allowed",         ETYPE_UNSECURE,         BUS_PARAM(logon_nid.unsecure_allowed),      0U, 0U },

    { true,     "ciphers",                  ETYPE_CIPHERS,          NULL /* custom implementation */,           0U, 0U },

    { true,     "cak",                      ETYPE_CAK,              NULL /* custom implementation */,           0U, 0U },
    { true,     "ckn",                      ETYPE_CKN,              NULL /* custom implementation */,           0U, 0U },
    { false,    "drv_macsec_mode",          ETYPE_DRV_MACSEC_MODE,  NULL /* custom implementation */,           0U, 0U },
    { false,    "intf_mode",                ETYPE_INTF_MODE,        BUS_PARAM(impl.intf_mode),                  0U, 1U },

    { false,    "mc_uart",                  ETYPE_STRING,           BUS_PARAM(impl.mc_uart),                    0U, 0U },
    { false,    "phy_vlan_bypass",          ETYPE_BOOL,             BUS_PARAM(impl.phy_settings.vlan_bypass),   0U, 1U },
    { false,    "phy_vlan_list",            ETYPE_VLANBYP_LIST,     NULL /* custom implementation */,           0U, 0U },
    { false,    "phy_proto_bypass",         ETYPE_PROTOBYP_LIST,    NULL /* custom implementation */,           0U, 0U },
    { false,    "phy_mac_bypass",           ETYPE_MACBYP_LIST,      NULL /* custom implementation */,           0U, 0U },
    { false,    "phy_transmit_sci",         ETYPE_BOOL,             BUS_PARAM(impl.phy_settings.transmit_sci),  0U, 1U },
    { false,    "phy_transmit_mtu",         ETYPE_UINT16,           BUS_PARAM(impl.phy_settings.transmit_mtu),  0U, 65535U },
};

static t_MKA_bus_config const bus_initial = {
    .enable = true,
    
    .port_capabilities = {
        .mka = true,
        .macsec = true,
        .announcements = false,
        .listener = false
    },

    .port_name = NULL,
    .port_number = 0,

    .kay = {
        .enable = true,
        .actor_priority = 128,
        .actor_role = MKA_ROLE_AUTO,
        .macsec_capable = MKA_MACSEC_INT_CONF_0,
        .macsec_desired = true,
        .replay_protect = false,
        .replay_protect_wnd = 0U,
        .delay_protect = true,
        .pcpt_activation = MKA_ACTIVATE_ALWAYS
    },

    .logon_nid = { // Currently unused
        .unauth_allowed = MKA_UNAUTH_NEVER,
        .unsecure_allowed = MKA_UNSECURE_NEVER
    },

    .logon_process = {
        .logon = true
    },

    .impl = {
        .phy_driver = {
            &MKA_PHY_UpdateSecY,
            &MKA_PHY_InitRxSC,
            &MKA_PHY_DeinitRxSC,
            &MKA_PHY_AddTxSA,
            &MKA_PHY_UpdateTxSA,
            &MKA_PHY_DeleteTxSA,
            &MKA_PHY_AddRxSA,
            &MKA_PHY_UpdateRxSA,
            &MKA_PHY_DeleteRxSA,
            &MKA_PHY_GetTxSANextPN,
            &MKA_PHY_GetMacSecStats
        },
        .key_mng = {
            &MKA_RetrieveCAKCKN,
            &MKA_RetrieveKEK,
            &MKA_RetrieveICK
        },
        .cipher_preference = {
            MKA_CS_INVALID,
            MKA_CS_INVALID,
            MKA_CS_INVALID,
            MKA_CS_INVALID,
            MKA_CS_INVALID
        },
        .conf_offset_preference = MKA_CONFIDENTIALITY_OFFSET_0,
        .intf_mode = MKA_INTF_MODE_STATIC,
        .mode = MKA_MACSEC_SOFTWARE,
        .mc_uart = NULL,
        .phy_settings = {
            .vlan_bypass = false,
            .vlan = { 0U },
            .proto_bypass = { MKA_L2_PROTO_EAPOL, 0U, 0U, 0U, 0U, 0U, 0U, 0U },
            .DA_bypass = { { { 0U }, false } },
            .transmit_sci = false,
            .transmit_mtu = 1468U,
        },
    }
};


/*******************        Func. prototypes  ***********************/
static bool cast_uint(yaml_event_t *event, char const*input, char const*ref, uint32_t min, uint32_t max, uint32_t base, uint32_t *value);
static bool handle_uint(yaml_parser_t *parser, yaml_event_t *event, char const*ref, uint32_t min, uint32_t max, uint32_t *value);
static bool handle_root_mapping(yaml_parser_t *parser, yaml_event_t *event, bool* presence);
static bool handle_interface_mapping(yaml_parser_t *parser, yaml_event_t *event, bool* presence);
static bool parse_elem_from_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem_list, size_t list_size, bool* presence);
static bool parse_elem(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_next(yaml_parser_t *parser, yaml_event_t *event);
static bool parse_next_expect_type(yaml_parser_t *parser, yaml_event_t *event, char const*ref, yaml_event_type_t type);
static bool check_missing_elements(yaml_event_t *event, char const* context, t_config_elem const* elem_list, size_t list_size, bool* presence);
static bool validate_interface(yaml_event_t *event, char* context, t_config_elem const* elem_list, size_t list_size, bool* presence);

static bool dynlist_hello_rampup_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value);
static bool stalist_cipher_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value);
static bool stalist_cak_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value);
static bool stalist_ckn_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value);
static bool stalist_vlanbyp_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value);
static bool stalist_protobyp_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value);
static bool stalist_macbyp_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value);
static bool handle_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, t_list_elem_handler elem_handler, uint32_t* count);

// Type parsers
static bool parse_elem_uint32(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_uint16(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_string(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_uint8(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_bool(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_log_level(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_role(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_replay(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_hello_rampup(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_macsec_mode(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_ciphers(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_cak(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_ckn(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_intf_mode(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_unauth_allowed(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_unsecure_allowed(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_drv_macsec_mode(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_vlan_bypass_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_proto_bypass_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);
static bool parse_elem_mac_bypass_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem);

static t_type_handlers const type_handlers[] = {
    {   ETYPE_UINT32,           parse_elem_uint32               },
    {   ETYPE_UINT16,           parse_elem_uint16               },
    {   ETYPE_STRING,           parse_elem_string               },
    {   ETYPE_UINT8,            parse_elem_uint8                },
    {   ETYPE_BOOL,             parse_elem_bool                 },
    {   ETYPE_LOG_LEVEL,        parse_elem_log_level            },
    {   ETYPE_ROLE,             parse_elem_role                 },
    {   ETYPE_REPLAY,           parse_elem_replay               },
    {   ETYPE_HELLO_RAMPUP,     parse_elem_hello_rampup         },
    {   ETYPE_HEX_LIST,         parse_elem_hello_rampup         },
    {   ETYPE_MACSEC_MODE,      parse_elem_macsec_mode          },
    {   ETYPE_CIPHERS,          parse_elem_ciphers              },
    {   ETYPE_CAK,              parse_elem_cak                  },
    {   ETYPE_CKN,              parse_elem_ckn                  },
    {   ETYPE_INTF_MODE,        parse_elem_intf_mode            },
    {   ETYPE_UNAUTH,           parse_elem_unauth_allowed       },
    {   ETYPE_UNSECURE,         parse_elem_unsecure_allowed     },
    {   ETYPE_DRV_MACSEC_MODE,  parse_elem_drv_macsec_mode      },
    {   ETYPE_VLANBYP_LIST,     parse_elem_vlan_bypass_list     },
    {   ETYPE_PROTOBYP_LIST,    parse_elem_proto_bypass_list    },
    {   ETYPE_MACBYP_LIST,      parse_elem_mac_bypass_list      },
};


/*******************        Func. definition  ***********************/

static bool cast_uint(yaml_event_t *event, char const*input, char const*ref, uint32_t min, uint32_t max, uint32_t base, uint32_t *value)
{
    bool result;

    *value = strtol(input, NULL, base);

    if ((0U == *value) && ('0' != input[0])) {
        FATAL_AT(event, "while importing [%s], integer casting error [%s]", ref, input);
        result = false;
    }
    else if ((*value < min) || (*value > max)) {
        FATAL_AT(event, "while importing [%s], value [%i] out of range %i..%i", ref, *value, min, max);
        result = false;
    }
    else {
        result = true;
    }

    return result;
}

static bool handle_uint(yaml_parser_t *parser, yaml_event_t *event, char const*ref, uint32_t min, uint32_t max, uint32_t *value)
{
    bool result = parse_next_expect_type(parser, event, ref, YAML_SCALAR_EVENT);

    if (result) {
        result = cast_uint(event, (char const*)event->data.scalar.value, ref, min, max, 10U, value);
    }

    return result;
}

static bool handle_root_mapping(yaml_parser_t *parser, yaml_event_t *event, bool* presence)
{
    bool result = true;

    if (YAML_SCALAR_EVENT != event->type) {
        FATAL_AT(event, "format error, expected sequence of scalar elements in global settings [%i].", event->type);
        result = false;
    }
    else if (STR_EQUAL("interfaces", event->data.scalar.value)) {
        bool interface_presence[MKA_ARRAY_SIZE(interface_elements)] = {0};
        uint_t map_depth = 1U;
        bool done = false;

        mka_num_buses_configured = 0U;
        result = parse_next_expect_type(parser, event, "interfaces", YAML_SEQUENCE_START_EVENT);

        while(result && !done) {
            if (!parse_next(parser, event)) {
                result = false;
                break;
            }

            map_depth += ((YAML_SEQUENCE_START_EVENT == event->type) || (YAML_MAPPING_START_EVENT == event->type)) ? 1U : 0U;
            map_depth -= ((YAML_SEQUENCE_END_EVENT == event->type) || (YAML_MAPPING_END_EVENT == event->type)) ? 1U : 0U;

            // begin interface
            if ((2U == map_depth) && (YAML_MAPPING_START_EVENT == event->type)) {
                if (mka_num_buses_configured >= MKA_NUM_BUSES) {
                    FATAL_AT(event, "stopping, reached maximum number of buses for this compilation: %i", MKA_NUM_BUSES);
                    result = false;
                }
                else {
                    // port_name from strdup; only true after re-configuring
                    if (NULL != mka_config.bus_config[mka_num_buses_configured].port_name) {
                        free((void*)mka_config.bus_config[mka_num_buses_configured].port_name);
                    }
                    if (NULL != mka_config.bus_config[mka_num_buses_configured].impl.mc_uart) {
                        free((void*)mka_config.bus_config[mka_num_buses_configured].impl.mc_uart);
                    }
                    (void)memcpy(&mka_config.bus_config[mka_num_buses_configured], &bus_initial, sizeof(bus_initial));
                    (void)memset(&keys[mka_num_buses_configured], 0, sizeof(keys[0]));
                }
                memset(interface_presence, 0, sizeof(interface_presence));

            } // end interface
            else if ((1U == map_depth) && (YAML_MAPPING_END_EVENT == event->type)) {
                char context[128];
                (void)sprintf(context, "in interface number %i (previous to the referenced line)", 1U + mka_num_buses_configured);
                result = validate_interface(event, context, interface_elements, MKA_ARRAY_SIZE(interface_elements), interface_presence);
                ++mka_num_buses_configured;

            } // end list
            else if (0U == map_depth) {
                done = true;
            }
            else {
                result = handle_interface_mapping(parser, event, interface_presence);
            }
        }
    }
    else {
        result = parse_elem_from_list(parser, event, root_elements, MKA_ARRAY_SIZE(root_elements), presence);
    }

    return result;
}

static bool handle_interface_mapping(yaml_parser_t *parser, yaml_event_t *event, bool* presence)
{
    static sint_t           current_bus = -1;
    static t_config_elem    interface_elements_relocated[MKA_ARRAY_SIZE(interface_elements)];

    bool result = true;

    if ((sint_t)mka_num_buses_configured != current_bus) {
        uint32_t i;
        current_bus = mka_num_buses_configured;
        memcpy(interface_elements_relocated, interface_elements, sizeof(interface_elements));

        for(i=0U; i<MKA_ARRAY_SIZE(interface_elements); ++i) {
            t_config_elem const*const template = &interface_elements[i];
            t_config_elem *const elem = &interface_elements_relocated[i];

            if (NULL != template->holder) {
                size_t parameter_offset = (size_t)template->holder - (size_t)&mka_config.bus_config[0];
                elem->holder = (void*)( (size_t)&mka_config.bus_config[current_bus] + (size_t)parameter_offset);
            }
        }
    }

    if (YAML_SCALAR_EVENT != event->type) {
        FATAL_AT(event, "format error, expected sequence of scalar elements in interface settings [%i].", event->type);
        result = false;
    }
    else {
        result = parse_elem_from_list(parser, event, interface_elements_relocated,
                                            MKA_ARRAY_SIZE(interface_elements), presence);
    }

    return result;
}

static bool validate_interface(yaml_event_t *event, char* context, t_config_elem const* elem_list, size_t list_size, bool* presence)
{
    t_MKA_bus_config*const cfg = &mka_config.bus_config[mka_num_buses_configured];
    t_bus_keys* key = &keys[mka_num_buses_configured];
    bool result = true;

    if (!check_missing_elements(event, context, elem_list, list_size, presence)) {
        result = false;
    }
    else {
        cfg->port_number = mka_num_buses_configured;

        MKA_ASSERT(MKA_DeriveKEK(&key->cak, &key->ckn, key->cak.length, &key->kek),
            "Cannot derive CAK/CKN into KEK key!");

        MKA_ASSERT(MKA_DeriveICK(MKA_ALGORITHM_AGILITY, &key->cak, &key->ckn, key->cak.length, &key->ick),
            "Cannot derive CAK/CKN into ICK key!");

        if ((cfg->impl.intf_mode == MKA_INTF_MODE_STATIC) && cfg->port_capabilities.macsec) {
            MKA_ASSERT(cfg->impl.cipher_preference[1] == MKA_CS_INVALID, 
                "In Static interface mode, the list of supported Ciphers must have a single entry.");
        }

        if (MKA_MACSEC_MEDIACONVERTER == cfg->impl.mode) {
            MKA_ASSERT(NULL != cfg->impl.mc_uart,
                "Parameter 'mc_uart' is mandatory when 'drv_macsec_mode' == MEDIACONVERTER.");
        }
        else {
            MKA_ASSERT(NULL == cfg->impl.mc_uart,
                "Parameter 'mc_uart' is incompatible with 'drv_macsec_mode' != MEDIACONVERTER.");

            MKA_ASSERT(0U == cfg->impl.phy_settings.vlan[0],
                "Parameter 'phy_vlan_list' is incompatible with 'drv_macsec_mode' != MEDIACONVERTER.");

            MKA_ASSERT((MKA_L2_PROTO_EAPOL == cfg->impl.phy_settings.proto_bypass[0]) && (0U == cfg->impl.phy_settings.proto_bypass[1]),
                "Parameter 'phy_proto_bypass' is incompatible with 'drv_macsec_mode' != MEDIACONVERTER.");

            MKA_ASSERT(!cfg->impl.phy_settings.DA_bypass[0].enable,
                "Parameter 'phy_mac_bypass' is incompatible with 'drv_macsec_mode' != MEDIACONVERTER.");
        }
    }

    return result;
}

static bool check_missing_elements(yaml_event_t *event, char const* context, t_config_elem const* elem_list, size_t list_size, bool* presence)
{
    char *missing_list = calloc(2048, 1);
    bool result = true;
    uint32_t i;

    for(i=0U; i<list_size; ++i) {
        if (elem_list[i].mandatory && !presence[i]) {
            strcat(missing_list, (missing_list[0] != '\0') ? ", " : "");
            strcat(missing_list, elem_list[i].name);
        }
    }

    if (missing_list[0] != '\0') {
        FATAL_AT(event, "%s, missing parameters: %s", context, missing_list);
        result = false;
    }

    free(missing_list);

    return result;
}

static bool parse_elem_from_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem_list, size_t list_size, bool* presence)
{
    bool result = true;
    bool found = false;
    uint8_t i;

    for(i=0U; (!found) && (i<list_size); ++i) {
        t_config_elem const* elem = &elem_list[i];

        if (STR_EQUAL(elem->name, event->data.scalar.value)) {
            if (presence[i]) {
                FATAL_AT(event, "duplicated setting [%s]", elem->name);
                result = false;
            }
            else {
                presence[i] = true;
                found = true;
                result = parse_elem(parser, event, elem);
            }
        }
    }

    if (result && !found) {
        FATAL_AT(event, "unrecognised configuration setting [%s].", event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool parse_elem_uint32(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    return handle_uint(parser, event, elem->name, elem->uint_min, elem->uint_max, (uint32_t*)elem->holder);
}

static bool parse_elem_uint16(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    uint16_t *holder = (uint16_t*)elem->holder;
    uint32_t tmp;
    bool result = handle_uint(parser, event, elem->name, elem->uint_min, elem->uint_max, &tmp);

    *holder = (uint16_t)tmp;

    return result;
}

static bool parse_elem_string(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    bool result = parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT);

    if (result) {
        char const **holder = (char const**)elem->holder;
        *holder = strdup((char const*)event->data.scalar.value);
    }

    return result;
}

static bool parse_elem_uint8(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    uint8_t *holder = (uint8_t*)elem->holder;
    uint32_t tmp;
    bool result = handle_uint(parser, event, elem->name, elem->uint_min, elem->uint_max, &tmp);

    *holder = (uint8_t)tmp;

    return result;
}

static bool parse_elem_bool(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    bool *holder = (bool*)elem->holder;
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("off", event->data.scalar.value)) {
        *holder = false;
    }
    else if (STR_EQUAL("false", event->data.scalar.value)) {
        *holder = false;
    }
    else if (STR_EQUAL("on", event->data.scalar.value)) {
        *holder = true;
    }
    else if (STR_EQUAL("true", event->data.scalar.value)) {
        *holder = true;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {on, true} or {off, false}", elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool parse_elem_log_level(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    uint8_t *holder = (uint8_t*)elem->holder;
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("error", event->data.scalar.value)) {
        *holder = MKA_LOGLEVEL_ERROR;
    }
    else if (STR_EQUAL("warning", event->data.scalar.value)) {
        *holder = MKA_LOGLEVEL_WARNING;
    }
    else if (STR_EQUAL("info", event->data.scalar.value)) {
        *holder = MKA_LOGLEVEL_INFO;
    }
    else if (STR_EQUAL("debug", event->data.scalar.value)) {
        *holder = MKA_LOGLEVEL_DEBUG;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {error, warning, info, debug}", elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool parse_elem_role(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_role *holder = (t_MKA_role*)elem->holder;
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("AUTO", event->data.scalar.value)) {
        *holder = MKA_ROLE_AUTO;
    }
    else if (STR_EQUAL("KEY_SERVER", event->data.scalar.value)) {
        *holder = MKA_ROLE_FORCE_KEY_SERVER;
    }
    else if (STR_EQUAL("KEY_CLIENT", event->data.scalar.value)) {
        *holder = MKA_ROLE_FORCE_KEY_CLIENT;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {auto, key_server, key_client}", elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool parse_elem_replay(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    bool result = true;

    if (!parse_elem_uint32(parser, event, elem)) {
        result = false;
    }
    else {
        cfg->kay.replay_protect = true;
    }

    return result;
}

static bool handle_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, t_list_elem_handler elem_handler, uint32_t* count)
{
    bool result = true;

    *count = 0U;

    if (!parse_next(parser, event)) {
        result = false;

    } /* Case scalar, assume string with list of elements separated by space */
    else if (YAML_SCALAR_EVENT == event->type) {
        char* str_list = strdup((char const*)event->data.scalar.value);
        char* s;

        for (s = strtok(str_list, " "); result && (s != NULL); s = strtok(NULL, " ")) {
            result = elem_handler(parser, event, elem, *count, s);
            ++(*count);
        }

        free(str_list);

    } /* Case YAML native list */
    else if (YAML_SEQUENCE_START_EVENT == event->type) {
        do {
            if (!parse_next(parser, event)) {
                result = false;
            }
            else if (YAML_SEQUENCE_END_EVENT == event->type) {
                // Nothing
            }
            else if (YAML_SCALAR_EVENT != event->type) {
                FATAL_AT(event, "format error while importing [%s], expecting type %s got type %s",
                    elem->name, type2string[YAML_SCALAR_EVENT], type2string[event->type]);
                result = false;
            }
            else {
                result = elem_handler(parser, event, elem, *count, (char const*)event->data.scalar.value);
                ++(*count);
            }

        } while(result && (YAML_SEQUENCE_END_EVENT != event->type));
    } /* Unknown list */
    else {
        FATAL_AT(event, "format error while importing [%s], expecting list or string with space-separated elements", elem->name);
        result = false;
    }

    return result;
}

static bool dynlist_hello_rampup_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value)
{
    uint32_t base = (ETYPE_HEX_LIST == elem->type) ? 16U : 10U;
    bool result = true;

    (void)parser;

    if (idx >= MKA_ARRAY_SIZE(mka_config.global_config.hello_rampup)) {
        FATAL_AT(event, "MKA hello rampup list too long! maximum periods: %li", MKA_ARRAY_SIZE(mka_config.global_config.hello_rampup));
        result = false;
    }
    else if (!cast_uint(event, value, elem->name, elem->uint_min, elem->uint_max, base, &mka_config.global_config.hello_rampup[idx])) {
        result = false;
    }
    else {
        ++mka_config.global_config.hello_rampup_number;
    }

    return result;
}

static bool parse_elem_hello_rampup(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    uint32_t count;

    // Reset list
    mka_config.global_config.hello_rampup_number = 0U;

    return handle_list(parser, event, elem, dynlist_hello_rampup_handler, &count);
}

static bool parse_elem_macsec_mode(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("disable", event->data.scalar.value)) {
        cfg->port_capabilities.macsec = false;
        cfg->kay.macsec_capable = MKA_MACSEC_NOT_IMPLEMENTED;
        cfg->kay.macsec_desired = false;
        for(uint_t i=0U; i<MKA_ARRAY_SIZE(cfg->impl.cipher_preference); ++i) {
            cfg->impl.cipher_preference[i] = MKA_CS_NULL;
        }
        cfg->impl.conf_offset_preference = MKA_CONFIDENTIALITY_NONE;
    }
    else if (STR_EQUAL("integrity", event->data.scalar.value)) {
        cfg->port_capabilities.macsec = true;
        cfg->kay.macsec_capable = MKA_MACSEC_INTEGRITY;
        cfg->kay.macsec_desired = true;
        cfg->impl.conf_offset_preference = MKA_CONFIDENTIALITY_NONE;
    }
    else if (STR_EQUAL("conf_0", event->data.scalar.value)) {
        cfg->port_capabilities.macsec = true;
        cfg->kay.macsec_capable = MKA_MACSEC_INT_CONF_0;
        cfg->kay.macsec_desired = true;
        cfg->impl.conf_offset_preference = MKA_CONFIDENTIALITY_OFFSET_0;
    }
    else if (STR_EQUAL("conf_30", event->data.scalar.value)) {
        cfg->port_capabilities.macsec = true;
        cfg->kay.macsec_capable = MKA_MACSEC_INT_CONF_0_30_50;
        cfg->kay.macsec_desired = true;
        cfg->impl.conf_offset_preference = MKA_CONFIDENTIALITY_OFFSET_30;
    }
    else if (STR_EQUAL("conf_50", event->data.scalar.value)) {
        cfg->port_capabilities.macsec = true;
        cfg->kay.macsec_capable = MKA_MACSEC_INT_CONF_0_30_50;
        cfg->kay.macsec_desired = true;
        cfg->impl.conf_offset_preference = MKA_CONFIDENTIALITY_OFFSET_50;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {disable, integrity, conf_0, conf_30, conf_50}",
                elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool stalist_cipher_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    bool result = true;
    uint64_t cipher = MKA_CS_NULL;

    (void)idx;
    (void)parser;
    (void)elem;

    // translate to uint64
    if (STR_EQUAL("GCM_AES_XPN_256", value)) {
#ifdef CONFIG_MACSEC_XPN_SUPPORT
        cipher = MKA_CS_ID_GCM_AES_XPN_256;
#else
        FATAL_AT(event, "while importing [%s], value [%s] invalid, this compilation has no XPN support.",
                elem->name, event->data.scalar.value);
#endif
    }
    else if (STR_EQUAL("GCM_AES_256", value)) {
        cipher = MKA_CS_ID_GCM_AES_256;
    }
    else if (STR_EQUAL("GCM_AES_XPN_128", value)) {
#ifdef CONFIG_MACSEC_XPN_SUPPORT
        cipher = MKA_CS_ID_GCM_AES_XPN_128;
#else
        FATAL_AT(event, "while importing [%s], value [%s] invalid, this compilation has no XPN support.",
                elem->name, event->data.scalar.value);
#endif
    }
    else if (STR_EQUAL("GCM_AES_128", value)) {
        cipher = MKA_CS_ID_GCM_AES_128;
    }
    else if (STR_EQUAL("NULL", value)) {
        cipher = MKA_CS_NULL;
    }
    else {
#ifdef CONFIG_MACSEC_XPN_SUPPORT
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {GCM_AES_XPN_256, GCM_AES_256, GCM_AES_XPN_128, GCM_AES_128, NULL}",
                elem->name, event->data.scalar.value);
#else
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {GCM_AES_256, GCM_AES_128, NULL} (XPN support missing)",
                elem->name, event->data.scalar.value);
#endif
        result = false;
    }

    if (!result) {
        // nothing
    }
    else if ((!cfg->port_capabilities.macsec) && (MKA_CS_NULL != cipher)) {
        MKA_LOG_WARNING("Bus %i cipher %s ignored, macsec is disabled!", mka_num_buses_configured, value);
    }
    else if (!cfg->port_capabilities.macsec) {
        // no action. null cipher is expected
    }
    else if (result) {
        bool done = false;

        for(uint_t i=0U; result && (!done) && (i<MKA_ARRAY_SIZE(cfg->impl.cipher_preference)); ++i) {
            // free slot
            if (MKA_CS_INVALID == cfg->impl.cipher_preference[i]) {
                cfg->impl.cipher_preference[i] = cipher;
                done = true;

            } // duplicated
            else if (cfg->impl.cipher_preference[i] == cipher) {
                FATAL_AT(event, "cipher list contains duplicated element [%s]", value);
                result = false;
            }
            else {
                // keep iterating
            }
        }

        if (result && !done) {
            FATAL_AT(event, "too many ciphers! implementation limited to %li", MKA_ARRAY_SIZE(cfg->impl.cipher_preference));
            result = false;
        }
    }

    return result;
}

static bool parse_elem_ciphers(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    uint32_t count;

    // empty list
    for(uint_t i=0U; i<MKA_ARRAY_SIZE(cfg->impl.cipher_preference); ++i) {
        cfg->impl.cipher_preference[i] = cfg->port_capabilities.macsec ? MKA_CS_INVALID : MKA_CS_NULL;
    }

    // iterate
    return handle_list(parser, event, elem, stalist_cipher_handler, &count);
}

static bool stalist_cak_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value)
{
    t_bus_keys* key = &keys[mka_num_buses_configured];
    uint32_t byte32;
    bool result = true;

    (void)parser;
    (void)elem;

    if (!cast_uint(event, value, "CAK key", 0U, 255U, 16, &byte32)) {
        result = false;
    }
    else if (idx >= MKA_KEY_MAX) {
        FATAL_AT(event, "CAK key too long! expecting at most %i bytes", MKA_KEY_MAX);
        result = false;
    }
    else {
        key->cak.key[idx] = (uint8_t)byte32;
        key->cak.length = idx+1U;
    }

    return result;
}

static bool parse_elem_cak(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    uint32_t count;
    bool result = true;

    if (!handle_list(parser, event, elem, stalist_cak_handler, &count)) {
        result = false;
    }
    else if ((MKA_KEY_128BIT != count) && (MKA_KEY_256BIT != count)) {
        FATAL_AT(event, "Invalid length [%i] for CAK key, expected 16 (128 bits) or 32 (256 bits).", count);
        result = false;
    }
    else {
        MKA_LOG_INFO("config/%i loaded CAK key of %i bits", mka_num_buses_configured, 8U*count);
    }

    return result;
}

static bool stalist_ckn_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value)
{
    t_bus_keys* key = &keys[mka_num_buses_configured];
    uint32_t byte32;
    bool result = true;

    (void)parser;
    (void)elem;

    if (!cast_uint(event, value, "CKN identifier", 0U, 255U, 16, &byte32)) {
        result = false;
    }
    else if (idx >= MKA_CKN_MAX) {
        FATAL_AT(event, "CKN identifier too long! expecting at most %i bytes", MKA_CKN_MAX);
        result = false;
    }
    else {
        key->ckn.name[idx] = (uint8_t)byte32;
        key->ckn.length = idx+1U;
    }

    return result;
}

static bool parse_elem_ckn(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    uint32_t count;
    bool result = true;

    if (!handle_list(parser, event, elem, stalist_ckn_handler, &count)) {
        result = false;
    }
    else if (0U == count) {
        FATAL_AT(event, "CKN identifier is empty!.");
        result = false;
    }
    else {
        MKA_LOG_INFO("config/%i loaded %i bytes as CKN", mka_num_buses_configured, count);
    }

    return result;
}

static bool parse_elem_intf_mode(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("static", event->data.scalar.value)) {
        cfg->impl.intf_mode = MKA_INTF_MODE_STATIC;
    }
    else if (STR_EQUAL("dynamic", event->data.scalar.value)) {
        cfg->impl.intf_mode = MKA_INTF_MODE_DYNAMIC;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {static, dynamic}",
                elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool parse_elem_unauth_allowed(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("NEVER", event->data.scalar.value)) {
        cfg->logon_nid.unauth_allowed = MKA_UNAUTH_NEVER;
    }
    else if (STR_EQUAL("IMMEDIATE", event->data.scalar.value)) {
        cfg->logon_nid.unauth_allowed = MKA_UNAUTH_IMMEDIATE;
        
    }
    else if (STR_EQUAL("AUTH_FAIL", event->data.scalar.value)) {
        cfg->logon_nid.unauth_allowed = MKA_UNAUTH_ON_AUTH_FAIL;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {never, immediate, on_auth_fail}",
                elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool parse_elem_unsecure_allowed(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("NEVER", event->data.scalar.value)) {
        cfg->logon_nid.unsecure_allowed = MKA_UNSECURE_NEVER;
    }
    else if (STR_EQUAL("IMMEDIATE", event->data.scalar.value)) {
        cfg->logon_nid.unsecure_allowed = MKA_UNSECURE_IMMEDIATE;
    }
    else if (STR_EQUAL("MKA_FAIL", event->data.scalar.value)) {
        cfg->logon_nid.unsecure_allowed = MKA_UNSECURE_ON_MKA_FAIL;
    }
    else if (STR_EQUAL("MKA_SERVER", event->data.scalar.value)) {
        cfg->logon_nid.unsecure_allowed = MKA_UNSECURE_PER_MKA_SERVER;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {never, immediate, on_mka_fail, mka_server}",
                elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool parse_elem_drv_macsec_mode(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    bool result = true;

    if (!parse_next_expect_type(parser, event, elem->name, YAML_SCALAR_EVENT)) {
        result = false;
    }
    else if (STR_EQUAL("SOFTWARE", event->data.scalar.value)) {
        cfg->impl.mode = MKA_MACSEC_SOFTWARE;
    }
    else if (STR_EQUAL("OFFLOADING", event->data.scalar.value)) {
        cfg->impl.mode = MKA_MACSEC_OFFLOADING;
    }
    else if (STR_EQUAL("MEDIACONVERTER", event->data.scalar.value)) {
        cfg->impl.mode = MKA_MACSEC_MEDIACONVERTER;
    }
    else {
        FATAL_AT(event, "while importing [%s], value [%s] invalid, possible values {software, offloading, mediaconverter}",
                elem->name, event->data.scalar.value);
        result = false;
    }

    return result;
}

static bool stalist_vlanbyp_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    uint16_t const max_vlans = sizeof(cfg->impl.phy_settings.vlan) / sizeof(cfg->impl.phy_settings.vlan[0]);
    bool const is_hex = ((value[0] == '0') && ((value[1] == 'x') || (value[1] == 'X')));
    uint32_t byte32;
    bool result = true;

    (void)parser;
    (void)elem;

    if (!cast_uint(event, is_hex ? &value[2U] : &value[0U], "VLAN", 1U, 4095U, is_hex ? 16U : 10U, &byte32)) {
        result = false;
    }
    else if (idx >= max_vlans) {
        FATAL_AT(event, "Too many bypass VLAN's, support is up to %i", max_vlans);
        result = false;
    }
    else {
        cfg->impl.phy_settings.vlan[idx] = (uint16_t)byte32;
    }

    return result;
}

static bool parse_elem_vlan_bypass_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    uint32_t count = 0U;
    bool result = true;

    memset(cfg->impl.phy_settings.vlan, 0, sizeof(cfg->impl.phy_settings.vlan));

    if (!handle_list(parser, event, elem, stalist_vlanbyp_handler, &count)) {
        result = false;
    }
    else {
        MKA_LOG_DEBUG0("config/%i loaded VLAN bypass list", mka_num_buses_configured, count);
    }

    return result;
}

static bool stalist_protobyp_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    uint16_t const max_protos = sizeof(cfg->impl.phy_settings.proto_bypass) / sizeof(cfg->impl.phy_settings.proto_bypass[0]);
    bool const is_hex = ((value[0] == '0') && ((value[1] == 'x') || (value[1] == 'X')));
    uint32_t byte32;
    bool result = true;

    (void)parser;
    (void)elem;

    if (!cast_uint(event, is_hex ? &value[2U] : &value[0U], "ethernet protocol", 0U, 65535U, is_hex ? 16U : 10U, &byte32)) {
        result = false;
    }
    else if (idx >= max_protos) {
        FATAL_AT(event, "Too many bypass ethertype's, support is up to %i", max_protos);
        result = false;
    }
    else {
        cfg->impl.phy_settings.proto_bypass[idx] = (uint16_t)byte32;
    }

    return result;
}

static bool parse_elem_proto_bypass_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    uint32_t count = 0U;
    bool result = true;

    memset(cfg->impl.phy_settings.proto_bypass, 0, sizeof(cfg->impl.phy_settings.proto_bypass));

    if (!handle_list(parser, event, elem, stalist_protobyp_handler, &count)) {
        result = false;
    }
    else {
        MKA_LOG_DEBUG0("config/%i loaded proto bypass list", mka_num_buses_configured, count);
    }

    return result;
}

static bool stalist_macbyp_handler(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem, uint32_t idx, char const*value)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    uint16_t const max_macs = sizeof(cfg->impl.phy_settings.DA_bypass) / sizeof(cfg->impl.phy_settings.DA_bypass[0]);
    t_MKA_PhyDrv_addr_bypass*const DA_bypass = &cfg->impl.phy_settings.DA_bypass[idx];
    bool result = true;
    uint32_t byte32;
    uint32_t i;

    if (idx >= max_macs) {
        FATAL_AT(event, "Too many MAC addresses to bypass, support is up to %i.", max_macs);
        result = false;
    }

    for(i=0U; (i<6U) && result; ++i) {
        if (!isxdigit(value[3*i]) || !isxdigit(value[3*i+1])) {
            FATAL_AT(event, "Invalid MAC format, expected HH:HH:HH:HH:HH:HH with hex digits.");
            result = false;
        }
        else if ((i < 5U) && (value[3*i+2] != ':')) {
            FATAL_AT(event, "Invalid MAC format, expected HH:HH:HH:HH:HH:HH separated with ':'.");
            result = false;
        }
        else if ((i == 5U) && (value[3*i+2] != '\0')) {
            FATAL_AT(event, "Invalid MAC format, expected HH:HH:HH:HH:HH:HH with no additional characters.");
            result = false;
        }
        else if (!cast_uint(event, &value[3*i], "MAC octet", 0U, 255U, 16U, &byte32)) {
            result = false;
        }
        else {
            DA_bypass->address[i] = (uint8_t)byte32;
        }
    }

    DA_bypass->enable = result;

    return result;
}

static bool parse_elem_mac_bypass_list(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    t_MKA_bus_config* const cfg = &mka_config.bus_config[mka_num_buses_configured];
    uint32_t count = 0U;
    bool result = true;

    memset(cfg->impl.phy_settings.DA_bypass, 0, sizeof(cfg->impl.phy_settings.DA_bypass));

    if (!handle_list(parser, event, elem, stalist_macbyp_handler, &count)) {
        result = false;
    }
    else {
        MKA_LOG_DEBUG0("config/%i loaded MAC addr bypass list", mka_num_buses_configured, count);
    }

    return result;
}

static bool parse_elem(yaml_parser_t *parser, yaml_event_t *event, t_config_elem const* elem)
{
    bool result = true;
    bool found = false;

    for(uint_t i=0U; result && (!found) && (i<MKA_ARRAY_SIZE(type_handlers)); ++i) {
        t_type_handlers const*const handler = &type_handlers[i];
        if (handler->type == elem->type) {
            found = true;
            result = handler->func(parser, event, elem);
        }
    }

    if (!found) {
        FATAL_AT(event, "internal error, unknown type [%i]", elem->type);
        result = false;
    }

    return result;
}

static bool parse_next(yaml_parser_t *parser, yaml_event_t *event)
{
    yaml_event_delete(event);
    bool const result = yaml_parser_parse(parser, event);

    if (!result) {
        FATAL("YAML parsing error at %li:%li, %s, %s",
            1+parser->problem_mark.line, parser->problem_mark.column, parser->context, parser->problem);
    }

    return result;
}

static bool parse_next_expect_type(yaml_parser_t *parser, yaml_event_t *event, char const*ref, yaml_event_type_t type)
{
    bool result = parse_next(parser, event);

    if (result && (event->type != type)) {
        FATAL_AT(event, "while importing %s, expecting type %s got type %s",
            ref, type2string[type], type2string[event->type]);
        result = false;
    }

    return result;
}

t_MKA_result MKA_RetrieveCAKCKN(t_MKA_bus bus, t_MKA_key * const cak, t_MKA_ckn * const ckn)
{
    t_bus_keys* key = &keys[bus];

    MKA_ASSERT((MKA_KEY_128BIT == key->cak.length) || (MKA_KEY_256BIT == key->cak.length),
            "Bus %i, request for non-configured CAK", bus);
    MKA_ASSERT((0 != key->ckn.length) && (MKA_CKN_MAX >= key->ckn.length),
            "Bus %i, request for non-configured key", bus);

    (void)memcpy(cak, &key->cak, sizeof(*cak));
    (void)memcpy(ckn, &key->ckn, sizeof(*ckn));

    return MKA_OK;
}

t_MKA_result MKA_RetrieveKEK(t_MKA_bus bus, t_MKA_key * const kek)
{
    t_bus_keys* key = &keys[bus];

    MKA_ASSERT((MKA_KEY_128BIT == key->kek.length) || (MKA_KEY_256BIT == key->kek.length),
            "Bus %i, request for non-configured CAK", bus);

    (void)memcpy(kek, &key->kek, sizeof(*kek));

    return MKA_OK;
}

t_MKA_result MKA_RetrieveICK(t_MKA_bus bus, t_MKA_key * const ick)
{
    t_bus_keys* key = &keys[bus];

    MKA_ASSERT((MKA_KEY_128BIT == key->ick.length) || (MKA_KEY_256BIT == key->ick.length),
            "Bus %i, request for non-configured CAK", bus);

    (void)memcpy(ick, &key->ick, sizeof(*ick));

    return MKA_OK;
}


t_MKA_config const* mka_config_load(char const* filename)
{
    bool result = true;

    yaml_parser_t parser;
    yaml_event_t event = {0};

    yaml_parser_initialize(&parser);

    /* Initialise variables */
    mka_num_buses_configured = 0U;
    mka_config.global_config.hello_rampup_number = 0U;

    /* Import file */
    FILE* const config_file = fopen(filename, "rb");

    if (NULL == config_file) {
        FATAL("cannot open file [%s].", filename);
        result = false;
    }
    else {
        yaml_parser_set_input_file(&parser, config_file);
    }

    if (result) {
        bool root_presence[MKA_ARRAY_SIZE(root_elements)] = {0};
        bool done = false;
        uint_t map_depth = 0;

        // Handle parser sequence of events in a loop
        while(result && !done) {
            /* Get the next event. */
            if (!parse_next(&parser, &event)) {
                result = false;
                break;
            }

            if (    (YAML_STREAM_START_EVENT == event.type) ||
                    (YAML_DOCUMENT_START_EVENT == event.type)) {
                // No further action
            }
            else if((YAML_DOCUMENT_END_EVENT == event.type) ||
                    (YAML_STREAM_END_EVENT == event.type)) {
                // No further action
            }
            else if ((0U == map_depth) && (YAML_MAPPING_START_EVENT == event.type)) {
                ++map_depth;
            }
            else if (0U == map_depth) {
                FATAL_AT(&event, "mapping expected as root element!");
                done = true;
                result = false;
                break;
            }
            else if ((1U == map_depth) && (YAML_MAPPING_END_EVENT == event.type)) {
                --map_depth;
            }
            else {
                map_depth += (YAML_MAPPING_START_EVENT == event.type) ? 1U : 0U;
                map_depth -= (YAML_MAPPING_END_EVENT == event.type) ? 1U : 0U;

                result = handle_root_mapping(&parser, &event, root_presence);
            }

            if (YAML_STREAM_END_EVENT == event.type) {
                done = true;
                result = check_missing_elements(&event, "in global parameters", root_elements, MKA_ARRAY_SIZE(root_elements), root_presence);

                if (0U == mka_num_buses_configured) {
                    FATAL("no interfaces configured, nothing to do!");
                    result = false;
                }
            }
        }

        (void)done;
    }

    // Cleanup
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);

    if (NULL != config_file) {
        fclose(config_file);
    }

    if (!result) {
        mka_config_free(&mka_config);
    }

    return result ? &mka_config : NULL;
}

void mka_config_free(t_MKA_config *config)
{
    t_MKA_bus bus;
    uint8_t i;

    // Global settings
    for(i=0U; i<MKA_ARRAY_SIZE(root_elements); ++i) {
        t_config_elem const*const elem_def = &root_elements[i];
        if ((ETYPE_STRING == elem_def->type) && (NULL != elem_def->holder)) {
            void**const variable = (void**)elem_def->holder;
            if (NULL != *variable) {
                free(*variable);
                *variable = NULL;
            }
        }
    }

    // Iterate all buses
    for(bus=0U; bus<MKA_NUM_BUSES; ++bus) {
        // Iterate bus settings
        for(i=0U; i<MKA_ARRAY_SIZE(interface_elements); ++i) {
            t_config_elem const*const elem_def = &interface_elements[i];

            if ((ETYPE_STRING == elem_def->type) && (NULL != elem_def->holder)) {
                // Pointer relocation to this specific bus
                size_t parameter_offset = (size_t)elem_def->holder - (size_t)&mka_config.bus_config[0];
                void**const variable = (void**)( (size_t)&mka_config.bus_config[bus] + (size_t)parameter_offset);

                if (NULL != *variable) {
                    // Release variable
                    free(*variable);
                    *variable = NULL;
                }
            }
        }

        // Reset bus settings to default
        memcpy(&mka_config.bus_config[bus], &bus_initial, sizeof(bus_initial));
    }
}

