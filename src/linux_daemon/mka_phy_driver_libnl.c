/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_phy_driver_libnl.c
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

#include <sys/types.h>
#include "mka_private.h"
#include "mka_phy_driver.h"
#include <bsd/string.h>
//#include <net/if_arp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/link.h>
#include <netlink/route/link/macsec.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define SCISTR MACSTR "::%hx"
#define SCI2STR(addr, port) MAC2STR(addr), htons(port)
#define MAC_ADDR_LEN 6
#define MI_LEN			12
#define UNUSED_SCI 0xffffffffffffffff

// 500 ms
#define TXSC_CACHE_EXPIRATION_NS 500000000

typedef u16 __bitwise be16;

typedef enum {
	CB_GET_PN,
	CB_GET_STATS
} t_libnl_cb_function;

typedef struct {
	t_MKA_stats_transmit_secy stats_tx_secy;
	t_MKA_stats_receive_secy stats_rx_secy;
	t_MKA_stats_transmit_sc stats_tx_sc;
	t_MKA_stats_receive_sc stats_rx_sc;
} t_libnl_stats;

// Information returned by get_txsc_info for each bus. This will be cached.
struct t_get_txsc_info {
	t_libnl_stats stats;
	t_MKA_pn txpn;
	t_MKA_pn rxpn;
};

// Cache
struct timespec txsc_info_cache_timestamp;
pthread_mutex_t txsc_info_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// Data for each bus
typedef struct {
	struct nl_sock *nl_sk;
    struct nl_cache *link_cache;
    struct nl_sock *genl_sk;
    int macsec_genl_id;
    bool init_done;
	uint32_t ifi;
	int parent_ifi;
	bool created_link;
	struct rtnl_link *link;
	char macsec_ifname[IFNAMSIZ + 1];
	char phys_ifname[IFNAMSIZ + 1];
	bool controlled_port_enabled;
	bool protect_frames;
	t_MKA_validate_frames validate_frames;
	bool encrypt;
	bool replay_protect;
	uint32_t replay_window;
	t_MKA_sci tx_sci;
	t_MKA_sci rx_sci;
	uint64_t cipher_suite;
#ifdef CONFIG_MACSEC_XPN_SUPPORT
	bool xpn;
#endif // CONFIG_MACSEC_XPN_SUPPORT
	struct t_get_txsc_info txsc_info_cache_data;
} t_MKA_libnl_status;

#ifdef CONFIG_MACSEC_XPN_SUPPORT
uint64_t xpn_ciphers[2] = {
	MKA_CS_ID_GCM_AES_XPN_128,
	MKA_CS_ID_GCM_AES_XPN_256
};
#endif // CONFIG_MACSEC_XPN_SUPPORT

t_MKA_libnl_status libnl_status[MKA_NUM_BUSES];

static struct nla_policy sa_policy[MACSEC_SA_ATTR_MAX + 1] = {
	[MACSEC_SA_ATTR_AN] = { .type = NLA_U8 },
	[MACSEC_SA_ATTR_ACTIVE] = { .type = NLA_U8 },
	[MACSEC_SA_ATTR_PN] = { .type = NLA_U32 },
	[MACSEC_SA_ATTR_KEYID] = { .type = NLA_BINARY },
};

static struct nla_policy sc_policy[MACSEC_RXSC_ATTR_MAX + 1] = {
	[MACSEC_RXSC_ATTR_SCI] = { .type = NLA_U64 },
	[MACSEC_RXSC_ATTR_ACTIVE] = { .type = NLA_U8 },
	[MACSEC_RXSC_ATTR_SA_LIST] = { .type = NLA_NESTED },
};

static struct nla_policy main_policy[MACSEC_ATTR_MAX + 1] = {
	[MACSEC_ATTR_IFINDEX] = { .type = NLA_U32 },
	[MACSEC_ATTR_SECY] = { .type = NLA_NESTED },
	[MACSEC_ATTR_TXSA_LIST] = { .type = NLA_NESTED },
	[MACSEC_ATTR_RXSC_LIST] = { .type = NLA_NESTED },
};

static int dump_callback(struct nl_msg *msg, void *argp)
{
	struct nlmsghdr *ret_hdr = nlmsg_hdr(msg);
	struct nlattr *tb_msg[MACSEC_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *) nlmsg_data(ret_hdr);
	int err;
	struct nlattr *nla;
	int rem;
	struct t_get_txsc_info *txsc_info_cache_data;

	err = nla_parse(tb_msg, MACSEC_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), main_policy);
	if (err < 0) {
		return 0;
	}

	if (!tb_msg[MACSEC_ATTR_IFINDEX]){
		return 0;
	}

	// Look for the relevant interface in the list of active buses
	t_MKA_libnl_status *this_libnl_status = NULL;
	for (uint32_t i=0;i<MKA_NUM_BUSES;i++){
		if (libnl_status[i].ifi == nla_get_u32(tb_msg[MACSEC_ATTR_IFINDEX])){
			this_libnl_status = &libnl_status[i];
		}
	}
	if (this_libnl_status == NULL){
		return 0;
	}
	if (ret_hdr->nlmsg_type != this_libnl_status->macsec_genl_id){
		return 0;
	}
	txsc_info_cache_data = &this_libnl_status->txsc_info_cache_data;
	// Zeroize the struct to make sure no old values are left from previous iterations if we now don't receive them.
	memset(txsc_info_cache_data, 0, sizeof(struct t_get_txsc_info));

	// Get TX PN
	if (tb_msg[MACSEC_ATTR_TXSA_LIST]) {
		nla_for_each_nested(nla, tb_msg[MACSEC_ATTR_TXSA_LIST], rem) {
			struct nlattr *tb[MACSEC_SA_ATTR_MAX + 1];

			err = nla_parse_nested(tb, MACSEC_SA_ATTR_MAX, nla,
						sa_policy);
			if (err < 0){
				continue;
			} if (!tb[MACSEC_SA_ATTR_AN]){
				continue;
			} if (!tb[MACSEC_SA_ATTR_PN]){
				continue;
			}
#ifdef CONFIG_MACSEC_XPN_SUPPORT
			if (this_libnl_status->xpn) {
				txsc_info_cache_data->txpn = nla_get_u64(tb[MACSEC_SA_ATTR_PN]);
			} else
#endif // CONFIG_MACSEC_XPN_SUPPORT
			{
				txsc_info_cache_data->txpn = nla_get_u32(tb[MACSEC_SA_ATTR_PN]);
			}
		}
	}

	// Get RX PN
	if (tb_msg[MACSEC_ATTR_RXSC_LIST]) {
		nla_for_each_nested(nla, tb_msg[MACSEC_ATTR_RXSC_LIST], rem) {
			struct nlattr *tb[MACSEC_RXSC_ATTR_MAX + 1];

			err = nla_parse_nested(tb, MACSEC_RXSC_ATTR_MAX, nla,
						sc_policy);
			if (err < 0){
				continue;
			}
			if (!tb[MACSEC_RXSC_ATTR_SCI]){
				continue;
			}
			if (!tb[MACSEC_RXSC_ATTR_SA_LIST]){
				continue;
			}

			nla_for_each_nested(nla, tb[MACSEC_RXSC_ATTR_SA_LIST],
						rem) {
				struct nlattr *tb_sa[MACSEC_SA_ATTR_MAX + 1];

				err = nla_parse_nested(tb_sa,
							MACSEC_SA_ATTR_MAX, nla,
							sa_policy);
				if (err < 0){
					continue;
				}
				if (!tb_sa[MACSEC_SA_ATTR_AN]){
					continue;
				}
				if (!tb_sa[MACSEC_SA_ATTR_PN]){
					continue;
				}
	#ifdef CONFIG_MACSEC_XPN_SUPPORT
				if (this_libnl_status->xpn) {
					txsc_info_cache_data->rxpn = nla_get_u64(tb_sa[MACSEC_SA_ATTR_PN]);
				} else
	#endif // CONFIG_MACSEC_XPN_SUPPORT
				{
					txsc_info_cache_data->rxpn = nla_get_u32(tb_sa[MACSEC_SA_ATTR_PN]);
				}

			}
		}
	}
	// Get stats

	if (tb_msg[MACSEC_ATTR_SECY_STATS]) {
		struct nlattr *tb[MACSEC_SECY_STATS_ATTR_MAX + 1];
		err = nla_parse_nested(tb, MACSEC_SECY_STATS_ATTR_MAX, tb_msg[MACSEC_ATTR_SECY_STATS],
					NULL);
		if (err == 0){
			txsc_info_cache_data->stats.stats_tx_secy.out_pkts_untagged = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_OUT_PKTS_UNTAGGED]);
			txsc_info_cache_data->stats.stats_rx_secy.in_pkts_untagged = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_IN_PKTS_UNTAGGED]);
			txsc_info_cache_data->stats.stats_tx_secy.out_pkts_too_long = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_OUT_PKTS_TOO_LONG]);
			txsc_info_cache_data->stats.stats_rx_secy.in_pkts_no_tag = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_TAG]);
			txsc_info_cache_data->stats.stats_rx_secy.in_pkts_bad_tag = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_IN_PKTS_BAD_TAG]);
			txsc_info_cache_data->stats.stats_rx_secy.in_pkts_no_sa = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_IN_PKTS_UNKNOWN_SCI]);
			txsc_info_cache_data->stats.stats_rx_secy.in_pkts_no_sa_error = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_SCI]);
			txsc_info_cache_data->stats.stats_rx_secy.in_pkts_overrun = nla_get_u64(tb[MACSEC_SECY_STATS_ATTR_IN_PKTS_OVERRUN]);
		}
	}
	if (tb_msg[MACSEC_ATTR_TXSC_STATS]){
		struct nlattr *tb[MACSEC_TXSC_STATS_ATTR_MAX + 1];
		err = nla_parse_nested(tb, MACSEC_TXSC_STATS_ATTR_MAX, tb_msg[MACSEC_ATTR_TXSC_STATS],
					NULL);
		if (err == 0){
			txsc_info_cache_data->stats.stats_tx_sc.out_pkts_protected = nla_get_u64(tb[MACSEC_TXSC_STATS_ATTR_OUT_PKTS_PROTECTED]);
			txsc_info_cache_data->stats.stats_tx_sc.out_pkts_encrypted = nla_get_u64(tb[MACSEC_TXSC_STATS_ATTR_OUT_PKTS_ENCRYPTED]);
			txsc_info_cache_data->stats.stats_tx_secy.out_octets_protected = nla_get_u64(tb[MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_PROTECTED]);
			txsc_info_cache_data->stats.stats_tx_secy.out_octets_encrypted = nla_get_u64(tb[MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_ENCRYPTED]);
		}
	}
	if (tb_msg[MACSEC_ATTR_RXSC_LIST]){
		struct nlattr *tb2[MACSEC_SECY_STATS_ATTR_MAX + 1];
		nla_for_each_nested(nla, tb_msg[MACSEC_ATTR_RXSC_LIST], rem) {
			struct nlattr *tb[MACSEC_RXSC_ATTR_MAX + 1];

			err = nla_parse_nested(tb, MACSEC_RXSC_ATTR_MAX, nla,
						NULL);
			if (err == 0){
				err = nla_parse_nested(tb2, MACSEC_RXSC_ATTR_MAX, tb[MACSEC_RXSC_ATTR_STATS],NULL);
				if (err == 0){
					txsc_info_cache_data->stats.stats_rx_secy.in_octets_validated = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED]);
					txsc_info_cache_data->stats.stats_rx_secy.in_octets_decrypted = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_OCTETS_DECRYPTED]);
					txsc_info_cache_data->stats.stats_rx_sc.in_pkts_unchecked = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNCHECKED]);
					txsc_info_cache_data->stats.stats_rx_sc.in_pkts_delayed = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_PKTS_DELAYED]);
					txsc_info_cache_data->stats.stats_rx_sc.in_pkts_ok = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_PKTS_OK]);
					txsc_info_cache_data->stats.stats_rx_sc.in_pkts_invalid = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_PKTS_INVALID]);
					txsc_info_cache_data->stats.stats_rx_sc.in_pkts_late = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_PKTS_LATE]);
					txsc_info_cache_data->stats.stats_rx_sc.in_pkts_not_valid = nla_get_u64(tb2[MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_VALID]);
				}
			}
		}
	}

	return 0;
}

static void txsc_cache_invalidate(){
	MKA_LOG_DEBUG1("Invalidating TxSC Cache");
	pthread_mutex_lock(&txsc_info_cache_mutex);
	txsc_info_cache_timestamp.tv_sec = 0;
	txsc_info_cache_timestamp.tv_nsec = 0;
	pthread_mutex_unlock(&txsc_info_cache_mutex);
}

// Initialize the connection. This function is called only once, at the beginning.
t_MKA_result libnl_init()
{
  for (unsigned int i=0;i<MKA_NUM_BUSES;i++){
    libnl_status->init_done = false;
	txsc_info_cache_timestamp.tv_sec = 0;
	txsc_info_cache_timestamp.tv_nsec = 0;
  }
  return MKA_OK;
}

static t_MKA_result libnl_per_bus_init(t_MKA_bus bus){
  int err;
  t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
  my_libnl_status->nl_sk = nl_socket_alloc();
	if (!my_libnl_status->nl_sk) {
		MKA_LOG_ERROR("failed to alloc nl socket");
		return MKA_NOT_OK;
	}

  err = nl_connect(my_libnl_status->nl_sk, NETLINK_ROUTE);
	if (err < 0) {
		MKA_LOG_ERROR("Unable to connect NETLINK_ROUTE socket: %s", nl_geterror(err));
		return MKA_NOT_OK;
	}

  err = rtnl_link_alloc_cache(my_libnl_status->nl_sk, AF_UNSPEC, &my_libnl_status->link_cache);
  if (err < 0) {
    MKA_LOG_ERROR("Unable to get link cache: %s", nl_geterror(err));
    return MKA_NOT_OK;
  }

  // init_genl_ctx
  my_libnl_status->genl_sk = nl_socket_alloc();
	if (!my_libnl_status->genl_sk) {
		MKA_LOG_ERROR("failed to alloc genl socket");
		return MKA_NOT_OK;
	}

	if (genl_connect(my_libnl_status->genl_sk) < 0) {
		MKA_LOG_ERROR("connection to genl socket failed");
	  return MKA_NOT_OK;
	}

	my_libnl_status->macsec_genl_id = genl_ctrl_resolve(my_libnl_status->genl_sk, "macsec");
	if (my_libnl_status->macsec_genl_id < 0) {
		MKA_LOG_ERROR("genl resolve failed");
		return MKA_NOT_OK;
	}

	nl_socket_modify_cb(my_libnl_status->genl_sk, NL_CB_VALID, NL_CB_CUSTOM, dump_callback,NULL);


  return MKA_OK;
}

static t_MKA_result deinit_interface(t_MKA_libnl_status *my_libnl_status)
{
	int err;
	err = rtnl_link_delete(my_libnl_status->nl_sk, my_libnl_status->link);
	rtnl_link_put(my_libnl_status->link);
	if (err < 0) {
		MKA_LOG_ERROR("couldn't delete link: err %d", err);
		return MKA_NOT_OK;
	}
	return MKA_OK;
}

t_MKA_result libnl_deinit()
{
	MKA_LOG_DEBUG1("Libnl adapter: cleaning up for shutdown");
	t_MKA_libnl_status *my_libnl_status;
	
	for (t_MKA_bus bus = 0; bus<MKA_NUM_BUSES; bus++){
		my_libnl_status = &libnl_status[bus];
		if (my_libnl_status->init_done){
			deinit_interface(my_libnl_status);
		}
		nl_socket_free(my_libnl_status->nl_sk);
		nl_socket_free(my_libnl_status->genl_sk);
		nl_cache_free(my_libnl_status->link_cache);
	}
  return MKA_OK;
}

static char* sci2a(t_MKA_sci const* sci) {
    static char buffer[128];
    (void)snprintf(buffer, sizeof(buffer), "%02X%02X%02X%02X%02X%02X-%04X",
        sci->addr[0], sci->addr[1], sci->addr[2], sci->addr[3], sci->addr[4], sci->addr[5], sci->port
    );
    return buffer;
}

static char* sak2a(t_MKA_key const* sak) {
    static char buffer[256] = "{ ";
    int ptr = 2;
    for(int i=0; i<sak->length; ++i) {
        ptr += snprintf(&buffer[ptr], sizeof(buffer)-ptr, "%02X ", sak->key[i]);
    }
    ptr += snprintf(&buffer[ptr], sizeof(buffer)-ptr, "}");
    return buffer;
}

static t_MKA_result nl_send_recv(struct nl_sock *sk, struct nl_msg *msg)
{
	int ret;

	ret = nl_send_auto_complete(sk, msg);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to send: %d (%s)",
			   ret, nl_geterror(-ret));
		return MKA_NOT_OK;
	}

	ret = nl_recvmsgs_default(sk);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to recv: %d (%s)",
			   ret, nl_geterror(-ret));
	    return MKA_NOT_OK;
	}

	return MKA_OK;
}

static t_MKA_result nla_put_rxsc_config(struct nl_msg *msg, u64 sci)
{
	struct nlattr *nest = nla_nest_start(msg, MACSEC_ATTR_RXSC_CONFIG);

	if (!nest)
		return MKA_NOT_OK;

	NLA_PUT_U64(msg, MACSEC_RXSC_ATTR_SCI, sci);

	nla_nest_end(msg, nest);

	return MKA_OK;

	nla_put_failure:
		return MKA_NOT_OK;
}

static u64 mka_sci_u64(t_MKA_sci const * sci)
{
 u64 sci_64 = sci->port;
 
 for(uint8_t i= 0;i<MKA_L2_ADDR_SIZE;i++) {
 	sci_64 |= ((u64)sci->addr[i]) << 8*(sizeof(u64)-1-i);
 }
 
 return MKA_HTONQ(sci_64);
}


static struct rtnl_link * lookup_sc(struct nl_cache *cache, int parent, u64 sci, uint64_t cipher_suite)
{
	struct rtnl_link *needle;
	void *match;

	needle = rtnl_link_macsec_alloc();
	if (!needle)
		return NULL;

	rtnl_link_set_link(needle, parent);
	rtnl_link_macsec_set_sci(needle, sci);
	MKA_LOG_DEBUG1("Looking for cipher suite: %llx", cipher_suite);
	// The parent link and SCI should be enough to univocally identify an SC, but in practice, it
	// is also necessary to specify the cipher suite. If this parameter is omitted, the search only
	// works when using the default cipher.
	rtnl_link_macsec_set_cipher_suite(needle, cipher_suite);

	match = nl_cache_find(cache, (struct nl_object *) needle);
	rtnl_link_put(needle);

	return (struct rtnl_link *) match;
}

#ifdef CONFIG_MACSEC_XPN_SUPPORT
static void set_xpn_flag(t_MKA_libnl_status *my_libnl_status)
{
	int n_ciphers = sizeof(xpn_ciphers) / sizeof(uint64_t);
	my_libnl_status->xpn = false;
	for (int i=0;i<n_ciphers;i++){
		if (my_libnl_status->cipher_suite == xpn_ciphers[i]) my_libnl_status->xpn = true;
	}
	MKA_LOG_DEBUG1("XPN flag is set to %d", my_libnl_status->xpn);
}
#endif // CONFIG_MACSEC_XPN_SUPPORT

static int macsec_drv_create_transmit_sc(
	t_MKA_bus bus,
	t_MKA_libnl_status *my_libnl_status,
	t_MKA_sci const * tx_sci,
	uint64_t cipher_suite)
{
	struct rtnl_link *link;
	char *ifname;
	u64 sci;
	int err;
	t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];

	MKA_LOG_DEBUG1("%s: create_transmit_sc -> " SCISTR,
		   cfg->port_name , SCI2STR(tx_sci->addr, tx_sci->port));

	if (!my_libnl_status->nl_sk) {
		MKA_LOG_ERROR("NULL rtnl socket");
		return MKA_NOT_OK;
	}

	link = rtnl_link_macsec_alloc();
	if (!link) {
		MKA_LOG_ERROR("couldn't allocate link");
		return MKA_NOT_OK;
	}

	rtnl_link_set_link(link, my_libnl_status->parent_ifi);

	rtnl_link_set_name(link, cfg->controlled_port_name);

	sci = mka_sci_u64(tx_sci);
	rtnl_link_macsec_set_sci(link, sci);

	memcpy(&my_libnl_status->tx_sci, tx_sci, sizeof(t_MKA_sci));

	// Set the cipher suite at startup, according to the configuration.
	// This is not protocol-compliant, but Linux does not support changing the cipher on an existing interface
	MKA_LOG_DEBUG1("Setting cipher suite: %llx", cipher_suite);

	// GCM_AES_128 is supposed to be 0x0080C20001000001ULL, but for some reason, it only works with the old, 
	// deprecated ID, hence this ugly workaround.
	if (cipher_suite == 0x0080C20001000001ULL) cipher_suite = 0x0080020001000001ULL;

	rtnl_link_macsec_set_cipher_suite(link, cipher_suite);
	my_libnl_status->cipher_suite = cipher_suite;
#ifdef CONFIG_MACSEC_XPN_SUPPORT
	set_xpn_flag(my_libnl_status);
#endif // CONFIG_MACSEC_XPN_SUPPORT


	my_libnl_status->created_link = true;

	// If requested hardware offload, set it:
#ifdef CONFIG_MACSEC_HW_OFFLOAD
	if (MKA_MACSEC_OFFLOADING == cfg->impl.mode)
	{
		MKA_LOG_DEBUG1("MACsec offloading requested");
		rtnl_link_macsec_set_offload(link, true);
	}
#else // compiled without offloading
	MKA_ASSERT(MKA_MACSEC_OFFLOADING != cfg->impl.mode, "While configuring bus %i, hardware offload is requested but not supported.", bus);
#endif

	err = rtnl_link_add(my_libnl_status->nl_sk, link, NLM_F_CREATE);
	if (err == -NLE_BUSY) {
		MKA_LOG_ERROR("link already exists!");
		return MKA_NOT_OK;
	} else if (err < 0) {
		rtnl_link_put(link);
		MKA_LOG_ERROR("couldn't create link: err %d", err);
		return MKA_NOT_OK;
	}

	rtnl_link_put(link);

	nl_cache_refill(my_libnl_status->nl_sk, my_libnl_status->link_cache);
	link = lookup_sc(my_libnl_status->link_cache, my_libnl_status->parent_ifi, sci, cipher_suite);
	if (!link) {
		MKA_LOG_ERROR("couldn't find link");
		return MKA_NOT_OK;
	}

	my_libnl_status->ifi = rtnl_link_get_ifindex(link);
	ifname = rtnl_link_get_name(link);
	MKA_LOG_DEBUG3("Create_transmit_sc: ifi=%d ifname=%s",
		   my_libnl_status->ifi, ifname);
	strlcpy(my_libnl_status->macsec_ifname, ifname, sizeof(my_libnl_status->macsec_ifname));
	rtnl_link_put(link);

	my_libnl_status->link = rtnl_link_macsec_alloc();
	if (!my_libnl_status->link) {
		MKA_LOG_ERROR("couldn't allocate link");
		return MKA_NOT_OK;
	}

	rtnl_link_set_name(my_libnl_status->link, my_libnl_status->macsec_ifname);

  return MKA_OK;
}

static t_MKA_result get_default_sci(t_MKA_bus bus, t_MKA_bus_config const*const cfg, t_MKA_sci * tx_sci){
	struct rtnl_link * link;
	struct nl_addr* addr;
	void* mac_addr;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	
	if (!my_libnl_status->nl_sk) {
		MKA_LOG_ERROR("NULL rtnl socket");
		return MKA_NOT_OK;
	}

	link = rtnl_link_get_by_name (my_libnl_status->link_cache, cfg->port_name) ;		
	addr = rtnl_link_get_addr (link); 	

	if (nl_addr_get_len(addr) != MAC_ADDR_LEN){
		MKA_LOG_ERROR("Received MAC address of unexpected length");
		return MKA_NOT_OK;
	}

	mac_addr = nl_addr_get_binary_addr(addr);

	memcpy(tx_sci->addr, mac_addr, MAC_ADDR_LEN);

	tx_sci->port = 1;
	return MKA_OK;
}

t_MKA_result MKA_PHY_UpdateSecY(t_MKA_bus bus, t_MKA_SECY_config const * config, t_MKA_sci const * tx_sci)
{
    int err;

    MKA_LOG_DEBUG1("Libnl adapter: Configuring SECY.");

    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];

	uint64_t requested_cipher_suite;
	// In static mode, we set the cipher that is the first on the list, and that's it
	if (cfg->impl.intf_mode == MKA_INTF_MODE_STATIC){
		requested_cipher_suite = cfg->impl.cipher_preference[0];
	} else { // In dynamic mode, obey whichever cipher the protocol says, unless we still don't know
		if (config->current_cipher_suite == 0xffffffffffffffff) requested_cipher_suite = cfg->impl.cipher_preference[0];
		else requested_cipher_suite = config->current_cipher_suite;
	}
	
	if ( // In dynamic mode, we need to teardown the interface if a different cipher is requested
		(my_libnl_status->init_done) && 
	    (my_libnl_status->cipher_suite != config->current_cipher_suite) &&
		(cfg->impl.intf_mode == MKA_INTF_MODE_DYNAMIC)
	) {
		MKA_LOG_INFO("Cipher change requested in dynamic mode. Tearing down controlled interface to create a new one with the different cipher");
		deinit_interface(my_libnl_status);
		my_libnl_status->init_done = false;
	}

    if (!my_libnl_status->init_done) {
      MKA_LOG_DEBUG2("Libnl init for this bus not done. Doing it now..");

			libnl_per_bus_init(bus);

				// Initialize aux_tx_sci to the value of an empty SCI
				t_MKA_sci aux_tx_sci;
				aux_tx_sci.addr[0] = 0xff;
				aux_tx_sci.addr[1] = 0xff;
				aux_tx_sci.addr[2] = 0xff;
				aux_tx_sci.addr[3] = 0xff;
				aux_tx_sci.addr[4] = 0xff;
				aux_tx_sci.addr[5] = 0xff;
				aux_tx_sci.port = 65535;
				// If the TX SCI matches the empty values, use a sane default instead
				if (memcmp(tx_sci, &aux_tx_sci, sizeof(t_MKA_sci)) == 0){
					MKA_LOG_INFO("TX Sci is still unknown, using default value..");
					get_default_sci(bus, cfg, &aux_tx_sci);
				} else {
					MKA_LOG_DEBUG1("Valid SCI received");
					memcpy(&aux_tx_sci, tx_sci, sizeof(t_MKA_sci));
				}
				t_MKA_sci *aux_tx_sci_pt = &aux_tx_sci;

			my_libnl_status->parent_ifi = rtnl_link_name2i(my_libnl_status->link_cache, cfg->port_name);
			if (my_libnl_status->parent_ifi == 0) {
				MKA_LOG_ERROR("couldn't find ifindex for interface %s", cfg->port_name);
				return MKA_NOT_OK;
			}
			strlcpy(my_libnl_status->phys_ifname, cfg->port_name, sizeof(my_libnl_status->phys_ifname));

			macsec_drv_create_transmit_sc(bus, my_libnl_status, aux_tx_sci_pt, requested_cipher_suite);

	}

	// If the requested port status (up or down) is different from the current one, update it
	if ((my_libnl_status->controlled_port_enabled != config->controlled_port_enabled) || !my_libnl_status->init_done){
		struct rtnl_link *change = rtnl_link_alloc();

		MKA_LOG_DEBUG1("Setting controlled port to %d", config->controlled_port_enabled);
		if (!change){
			MKA_LOG_ERROR("Could not allocate rtnl link for controlled port");
			return MKA_NOT_OK;
		}

		rtnl_link_set_name(change, my_libnl_status->macsec_ifname);

		if (config->controlled_port_enabled)
			rtnl_link_set_flags(change, IFF_UP);
		else
			rtnl_link_unset_flags(change, IFF_UP);

		err = rtnl_link_change(my_libnl_status->nl_sk, change, change, 0);
		if (err < 0)
			return err;

		rtnl_link_put(change);

		my_libnl_status->controlled_port_enabled = config->controlled_port_enabled;
	}

	// If the requested protect frames value is different from the current one, update it
	if ((my_libnl_status->protect_frames != config->protect_frames) || !my_libnl_status->init_done) {
		MKA_LOG_DEBUG1("Setting protect_frames=%d",
				config->protect_frames);
		rtnl_link_macsec_set_protect(my_libnl_status->link, config->protect_frames);
		my_libnl_status->protect_frames = config->protect_frames;
	}

	// If the requested validate frames value is different from the current one, update it
	if ((my_libnl_status->validate_frames != config->validate_frames) || !my_libnl_status->init_done) {
		enum macsec_validation_type validate = MACSEC_VALIDATE_STRICT;
		if (config->validate_frames == MKA_VALIDATE_DISABLED){
			MKA_LOG_DEBUG1("Setting validate_frames=DISABLED");
			validate = MACSEC_VALIDATE_DISABLED;
		} else if (config->validate_frames == MKA_VALIDATE_CHECKED){
            MKA_LOG_DEBUG1("Setting validate_frames=CHECKED");
			validate = MACSEC_VALIDATE_CHECK;
		} else if (config->validate_frames == MKA_VALIDATE_STRICT){
            MKA_LOG_DEBUG1("Setting validate_frames=STRICT");
			validate = MACSEC_VALIDATE_STRICT;
		}
		rtnl_link_macsec_set_validation_type(my_libnl_status->link, validate);
		my_libnl_status->validate_frames = config->validate_frames;
	}

	// If the requested encryption status (on or off) is different from the current one, update it
	// Confidentiality offsets are not supported on Linux, so they are ignored. If confidentiality is requested, the offset is always 0.
	bool encrypt;
	if (config->confidentiality_offset != MKA_CONFIDENTIALITY_NONE) encrypt = true;
	else encrypt = false;
	if ((my_libnl_status->encrypt != encrypt) || !my_libnl_status->init_done) {
		MKA_LOG_DEBUG1("Setting encrypt=%d", encrypt);
		rtnl_link_macsec_set_encrypt(my_libnl_status->link, encrypt);
		my_libnl_status->encrypt = encrypt;
	}

	// If requested replay protection or replay window are different from their current values, set them
	if (
		(my_libnl_status->replay_protect != config->replay_protect) ||
		(my_libnl_status->replay_window != config->replay_window) ||
		!my_libnl_status->init_done
	) {
		MKA_LOG_DEBUG1("Setting replay_protect=%d replay_window=%d",
				config->replay_protect,
				config->replay_window);
		rtnl_link_macsec_set_replay_protect(my_libnl_status->link,
							config->replay_protect);
		if (config->replay_protect)
			rtnl_link_macsec_set_window(my_libnl_status->link,
							config->replay_window);

		my_libnl_status->replay_protect = config->replay_protect;
		my_libnl_status->replay_window = config->replay_window;
	}

	// If the requested cipher suite differs from the current cipher suite, set it.
	// This block is commented because Linux does not support changing the cipher dinamically.
	// To be uncommented if the feature is ever implemented
	/*
	if ((my_libnl_status->cipher_suite != config->current_cipher_suite) || (!my_libnl_status->init_done)){
		MKA_LOG_DEBUG1("Setting cipher suite: %llu", config->current_cipher_suite);
		rtnl_link_macsec_set_cipher_suite(my_libnl_status->link, config->current_cipher_suite);
		my_libnl_status->cipher_suite = config->current_cipher_suite;
	}
	*/
	if (my_libnl_status->cipher_suite != config->current_cipher_suite){
		MKA_LOG_WARNING("Configured Cipher suite is %llx, but negotiated %llx. Dynamic cipher negotiation is not supported by Linux", my_libnl_status->cipher_suite, config->current_cipher_suite);
	}


	


	// Finally, commit the new link attributes
	err = rtnl_link_add(my_libnl_status->nl_sk, my_libnl_status->link, 0);
	if (err < 0){
		MKA_LOG_ERROR("Error adding link: %d", err);
		nl_perror(err, "Error adding link");
		return MKA_NOT_OK;
	} else {
		MKA_LOG_DEBUG1("Link modified OK");
	}

	my_libnl_status->init_done = true;
    return MKA_OK;
}

static struct nl_msg * msg_prepare(t_MKA_bus bus, enum macsec_nl_commands cmd,
				   unsigned int ifindex)
{
	struct nl_msg *msg;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];

	msg = nlmsg_alloc();
	if (!msg) {
		MKA_LOG_ERROR("failed to alloc message");
		return NULL;
	}

	if (!genlmsg_put(msg, 0, 0, my_libnl_status->macsec_genl_id, 0, 0, cmd, 0)) {
		MKA_LOG_ERROR("failed to put header");
		goto nla_put_failure;
	}

	NLA_PUT_U32(msg, MACSEC_ATTR_IFINDEX, ifindex);

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

t_MKA_result MKA_PHY_InitRxSC(t_MKA_bus bus, t_MKA_sci const * sci)
{
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	struct nl_msg *msg;
	int ret = -1;

	MKA_LOG_DEBUG1("Libnl adapter: Starting reception secure channel, SCI: %s", sci2a(sci));

	msg = msg_prepare(bus, MACSEC_CMD_ADD_RXSC, my_libnl_status->ifi);
	if (!msg) {
		MKA_LOG_ERROR("Error on message prepare");
		return MKA_NOT_OK;
	}


	if (nla_put_rxsc_config(msg, mka_sci_u64(sci)))
		goto nla_put_failure;

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to communicate: %d (%s)",
				ret, nl_geterror(-ret));
	}
	txsc_cache_invalidate();

	memcpy(&my_libnl_status->rx_sci, sci, sizeof(t_MKA_sci));

nla_put_failure:
	nlmsg_free(msg);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}
t_MKA_result MKA_PHY_DeinitRxSC(t_MKA_bus bus, t_MKA_sci const * sci)
{
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	struct nl_msg *msg;
	int ret = -1;

	MKA_LOG_DEBUG1("Libnl adapter: Stopping reception secure channel, SCI: %s", sci2a(sci));

	msg = msg_prepare(bus, MACSEC_CMD_DEL_RXSC, my_libnl_status->ifi);
	if (!msg)
		return ret;

	if (nla_put_rxsc_config(msg, mka_sci_u64(sci)))
		goto nla_put_failure;

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to communicate: %d (%s)",
			   ret, nl_geterror(-ret));
	}
	txsc_cache_invalidate();

nla_put_failure:
	nlmsg_free(msg);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}
t_MKA_result MKA_PHY_AddTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active)
{
    MKA_LOG_DEBUG1("Libnl adapter: Adding transmission secure association, AN: %i sak: %s", an, sak2a(sak));
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	struct nl_msg *msg;
	struct nlattr *nest;
	int ret = -1;

	MKA_LOG_DEBUG1("Create_transmit_sa -> %d on "
		   SCISTR " (enable_transmit=%d next_pn=%u)",
		   an,
		   SCI2STR(my_libnl_status->tx_sci.addr, my_libnl_status->tx_sci.port),
		   active, next_pn);

	msg = msg_prepare(bus, MACSEC_CMD_ADD_TXSA, my_libnl_status->ifi);
	if (!msg) {
		MKA_LOG_ERROR("Error on message prepare");
		return MKA_NOT_OK;
	}

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);
#ifdef CONFIG_MACSEC_XPN_SUPPORT
	if (my_libnl_status->xpn) {
		NLA_PUT_U64(msg, MACSEC_SA_ATTR_PN, next_pn);
		NLA_PUT_U32(msg, MACSEC_SA_ATTR_SSCI, MKA_HTONL(ssci));
		NLA_PUT(msg, MACSEC_SA_ATTR_SALT, salt->length, salt->key);
	}
	else
#endif // CONFIG_MACSEC_XPN_SUPPORT
    {
        NLA_PUT_U32(msg, MACSEC_SA_ATTR_PN, next_pn);
    }
	NLA_PUT(msg, MACSEC_SA_ATTR_KEYID, sizeof(t_MKA_ki), ki);
	NLA_PUT(msg, MACSEC_SA_ATTR_KEY, sak->length, sak->key);
	NLA_PUT_U8(msg, MACSEC_SA_ATTR_ACTIVE, active);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to communicate: %d (%s)",
			   ret, nl_geterror(-ret));
	}
	txsc_cache_invalidate();

nla_put_failure:
	nlmsg_free(msg);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}
t_MKA_result MKA_PHY_UpdateTxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active)
{
	struct nl_msg *msg;
	struct nlattr *nest;
	int ret = -1;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];

	MKA_LOG_DEBUG1("Update Transmit_sa -> %d on "
		SCISTR, an,
		SCI2STR(my_libnl_status->tx_sci.addr, my_libnl_status->tx_sci.port));

	// Set SA active/inactive
	msg = msg_prepare(bus, MACSEC_CMD_UPD_TXSA, my_libnl_status->ifi);
	if (!msg){
		MKA_LOG_ERROR("Error on message prepare");
		return ret;
	}

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);
	NLA_PUT_U8(msg, MACSEC_SA_ATTR_ACTIVE, !!active);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0)
		MKA_LOG_ERROR("%s: failed to communicate: %d (%s)",
			   __func__, ret, nl_geterror(-ret));
	
	//Set encoding_sa
	rtnl_link_macsec_set_encoding_sa(my_libnl_status->link, an);
	ret = rtnl_link_add(my_libnl_status->nl_sk, my_libnl_status->link, 0);
	if (ret < 0){
		MKA_LOG_ERROR("Error adding link: %d", ret);
		nl_perror(ret, "Error adding link");
	} else {
		MKA_LOG_DEBUG1("Link modified OK");
	}
	txsc_cache_invalidate();


nla_put_failure:
	nlmsg_free(msg);
	return ret;
}
t_MKA_result MKA_PHY_DeleteTxSA(t_MKA_bus bus, uint8_t an)
{
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	struct nl_msg *msg;
	struct nlattr *nest;
	int ret = -1;

	MKA_LOG_DEBUG1("Delete_transmit_sa -> %d on "
		   SCISTR, an,
		   SCI2STR(my_libnl_status->tx_sci.addr, my_libnl_status->tx_sci.port));
	
	// Set SA inactive
	msg = msg_prepare(bus, MACSEC_CMD_UPD_TXSA, my_libnl_status->ifi);
	if (!msg){
		MKA_LOG_ERROR("Error on message prepare");
		return ret;
	}

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);
	NLA_PUT_U8(msg, MACSEC_SA_ATTR_ACTIVE, false);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0)
		MKA_LOG_ERROR("%s: failed to communicate: %d (%s)",
			   __func__, ret, nl_geterror(-ret));

	// Now delete the disabled SA
	msg = msg_prepare(bus, MACSEC_CMD_DEL_TXSA, my_libnl_status->ifi);
	if (!msg) {
		MKA_LOG_ERROR("Error on message prepare");
		return MKA_NOT_OK;
	}

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to communicate: %d (%s)",
			   ret, nl_geterror(-ret));
	}
	txsc_cache_invalidate();

nla_put_failure:
	nlmsg_free(msg);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}
t_MKA_result MKA_PHY_AddRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, t_MKA_ssci ssci, t_MKA_key const * sak, t_MKA_key const * hash, t_MKA_key const * salt, t_MKA_ki const * ki, bool active)
{
    t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	struct nl_msg *msg;
	struct nlattr *nest;
	int ret = -1;

	MKA_LOG_DEBUG1("create_receive_sa -> %d on " SCISTR
		   " (enable_receive=%d next_pn=%u)",
		   an,
		   SCI2STR(my_libnl_status->rx_sci.addr, my_libnl_status->rx_sci.port),
		   active, next_pn);

	msg = msg_prepare(bus, MACSEC_CMD_ADD_RXSA, my_libnl_status->ifi);
	if (!msg) {
		MKA_LOG_ERROR("Error on message prepare");
		return MKA_NOT_OK;
	}
	
	if (nla_put_rxsc_config(msg, mka_sci_u64(&my_libnl_status->rx_sci)))
		goto nla_put_failure;

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);
	NLA_PUT_U8(msg, MACSEC_SA_ATTR_ACTIVE, active);
#ifdef CONFIG_MACSEC_XPN_SUPPORT
	if (my_libnl_status->xpn) {
		NLA_PUT_U64(msg, MACSEC_SA_ATTR_PN, next_pn);
		NLA_PUT_U32(msg, MACSEC_SA_ATTR_SSCI, MKA_HTONL(ssci));
		NLA_PUT(msg, MACSEC_SA_ATTR_SALT, salt->length, salt->key);
	}
	else
#endif // CONFIG_MACSEC_XPN_SUPPORT
    {
        NLA_PUT_U32(msg, MACSEC_SA_ATTR_PN, next_pn);
    }
	NLA_PUT(msg, MACSEC_SA_ATTR_KEYID, sizeof(t_MKA_ki), ki);
	NLA_PUT(msg, MACSEC_SA_ATTR_KEY, sak->length, sak->key);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to communicate: %d (%s)",
			   ret, nl_geterror(-ret));
	}
	txsc_cache_invalidate();

nla_put_failure:
	nlmsg_free(msg);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}
t_MKA_result MKA_PHY_UpdateRxSA(t_MKA_bus bus, uint8_t an, t_MKA_pn next_pn, bool active)
{
	struct nl_msg *msg;
	struct nlattr *nest;
	int ret = -1;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];

	MKA_LOG_DEBUG1("Update Receive_sa -> %d on "
		   SCISTR, an,
		   SCI2STR(my_libnl_status->rx_sci.addr, my_libnl_status->rx_sci.port));


	// Set SA active/inactive
	msg = msg_prepare(bus, MACSEC_CMD_UPD_RXSA, my_libnl_status->ifi);
	if (!msg){
		MKA_LOG_ERROR("Error on message prepare");
		return ret;
	}

	if (nla_put_rxsc_config(msg, mka_sci_u64(&my_libnl_status->rx_sci))){
		MKA_LOG_ERROR("Error in nla_put_rxsc_config");
		goto nla_put_failure;
	}
		

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);
	NLA_PUT_U8(msg, MACSEC_SA_ATTR_ACTIVE, !!active);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0)
		MKA_LOG_ERROR("%s: failed to communicate: %d (%s)",
			   __func__, ret, nl_geterror(-ret));
	
	// Set receive lowest PN
	MKA_LOG_DEBUG1("set_receive_lowest_pn -> %d: %d",
		an, next_pn);

	msg = msg_prepare(bus, MACSEC_CMD_UPD_RXSA, my_libnl_status->ifi);
	if (!msg){
		MKA_LOG_ERROR("Error on message prepare");
		return ret;
	}

	if (nla_put_rxsc_config(msg, mka_sci_u64(&my_libnl_status->rx_sci))){
		MKA_LOG_ERROR("Error in nla_put_rxsc_config");
		goto nla_put_failure;
	}

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);
#ifdef CONFIG_MACSEC_XPN_SUPPORT
	if (my_libnl_status->xpn) {
        NLA_PUT_U64(msg, MACSEC_SA_ATTR_PN, next_pn);
    }
    else
#endif // CONFIG_MACSEC_XPN_SUPPORT
    {
        NLA_PUT_U32(msg, MACSEC_SA_ATTR_PN, next_pn);
    }

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0)
		MKA_LOG_ERROR("%s: failed to communicate: %d (%s)",
			   __func__, ret, nl_geterror(-ret));

nla_put_failure:
	nlmsg_free(msg);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}
t_MKA_result MKA_PHY_DeleteRxSA(t_MKA_bus bus, uint8_t an)
{
	struct nl_msg *msg;
	struct nlattr *nest;
	int ret = -1;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];

	MKA_LOG_DEBUG1("Delete_receive_sa -> %d on "
		SCISTR, an,
		SCI2STR(my_libnl_status->rx_sci.addr, my_libnl_status->rx_sci.port));

	// Set SA inactive
	msg = msg_prepare(bus, MACSEC_CMD_UPD_RXSA, my_libnl_status->ifi);
	if (!msg){
		MKA_LOG_ERROR("Error on message prepare");
		return ret;
	}

	if (nla_put_rxsc_config(msg, mka_sci_u64(&my_libnl_status->rx_sci))){
		MKA_LOG_ERROR("Error in nla_put_rxsc_config");
		goto nla_put_failure;
	}
		

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);
	NLA_PUT_U8(msg, MACSEC_SA_ATTR_ACTIVE, false);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0)
		MKA_LOG_ERROR("%s: failed to communicate: %d (%s)",
			   __func__, ret, nl_geterror(-ret));


	// Now delete the disabled SA
	msg = msg_prepare(bus, MACSEC_CMD_DEL_RXSA, my_libnl_status->ifi);
	if (!msg) {
		MKA_LOG_ERROR("Error on message prepare");
		return MKA_NOT_OK;
	}

	if (nla_put_rxsc_config(msg, mka_sci_u64(&my_libnl_status->rx_sci)))
		goto nla_put_failure;

	nest = nla_nest_start(msg, MACSEC_ATTR_SA_CONFIG);
	if (!nest)
		goto nla_put_failure;

	NLA_PUT_U8(msg, MACSEC_SA_ATTR_AN, an);

	nla_nest_end(msg, nest);

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0) {
		MKA_LOG_ERROR("failed to communicate: %d (%s)",
			   ret, nl_geterror(-ret));
	}
	txsc_cache_invalidate();

nla_put_failure:
	nlmsg_free(msg);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}



static t_MKA_result txsc_cache_is_hit(){
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC,&now);
	bool cache_miss = false;
	if (now.tv_sec - txsc_info_cache_timestamp.tv_sec > 1){
		MKA_LOG_DEBUG1("More than 1 second elapsed, cache MISS\n");
		cache_miss = true;
	} else if (now.tv_sec - txsc_info_cache_timestamp.tv_sec == 1){
		if ((now.tv_nsec + 1000000000) - txsc_info_cache_timestamp.tv_nsec  > TXSC_CACHE_EXPIRATION_NS){
			MKA_LOG_DEBUG1(" Elapsed %d ns > %d, cache MISS", (now.tv_nsec + 1000000000) - txsc_info_cache_timestamp.tv_nsec,TXSC_CACHE_EXPIRATION_NS);
			cache_miss = true;
		} else {
			MKA_LOG_DEBUG1(" Elapsed %d ns < %d, cache HIT", (now.tv_nsec + 1000000000) - txsc_info_cache_timestamp.tv_nsec,TXSC_CACHE_EXPIRATION_NS);
		}
	} else {
		if (now.tv_nsec - txsc_info_cache_timestamp.tv_nsec > TXSC_CACHE_EXPIRATION_NS){
			MKA_LOG_DEBUG1(" Elapsed %d ns > %d, cache MISS", now.tv_nsec - txsc_info_cache_timestamp.tv_nsec, TXSC_CACHE_EXPIRATION_NS);
			cache_miss = true;
		} else {
			MKA_LOG_DEBUG1(" Elapsed %d ns < %d, cache HIT", now.tv_nsec - txsc_info_cache_timestamp.tv_nsec, TXSC_CACHE_EXPIRATION_NS);
		}
	}

	if (cache_miss == true) return false; // Cache miss
	else return true; // Cache hit	
}

// This function will update the txsc_info_cache_data structure inside the t_MKA_libnl_status structure of
// each bus, only if the cache time is expired.
static t_MKA_result txsc_cache_update(t_MKA_bus bus){
	struct nl_msg *msg;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	int ret = 1;
	pthread_mutex_lock(&txsc_info_cache_mutex);

	if (txsc_cache_is_hit()) {
		pthread_mutex_unlock(&txsc_info_cache_mutex);
		return MKA_OK;
	}

	clock_gettime(CLOCK_MONOTONIC,&txsc_info_cache_timestamp);

	msg = nlmsg_alloc();
	if (!msg) {
		MKA_LOG_ERROR("%s: failed to alloc message",
			   __func__);
		return MKA_NOT_OK;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, my_libnl_status->macsec_genl_id, 0,
			 NLM_F_DUMP, MACSEC_CMD_GET_TXSC, 0)) {
		MKA_LOG_ERROR("%s: failed to put header",
			   __func__);
		goto out_free_msg;
	}

	ret = nl_send_recv(my_libnl_status->genl_sk, msg);
	if (ret < 0)
		MKA_LOG_ERROR("failed to communicate: %d (%s)",
			   ret, nl_geterror(-ret));

out_free_msg:
	nlmsg_free(msg);
	pthread_mutex_unlock(&txsc_info_cache_mutex);
	if (ret == 0) return MKA_OK;
	else return MKA_NOT_OK;
}

t_MKA_result MKA_PHY_GetTxSANextPN(t_MKA_bus bus, uint8_t an, t_MKA_pn* next_pn)
{
	t_MKA_result err;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	if (!my_libnl_status->init_done){
		return MKA_OK;
	}
	MKA_LOG_DEBUG1("Libnl adapter: MKA_PHY_GetTxSANextPN");

	err = txsc_cache_update(bus);
	pthread_mutex_lock(&txsc_info_cache_mutex);
	*next_pn = my_libnl_status->txsc_info_cache_data.txpn;
	pthread_mutex_unlock(&txsc_info_cache_mutex);
	MKA_LOG_DEBUG1("%s: err %d result %d", __func__, err,
		   *next_pn);
	return err;
}

t_MKA_result MKA_PHY_GetMacSecStats(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy,
                                    t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc)
{
	t_MKA_result err;
	t_MKA_libnl_status *my_libnl_status = &libnl_status[bus];
	if (!my_libnl_status->init_done){
		return MKA_OK;
	}

	err = txsc_cache_update(bus);

	if (err == MKA_OK){
		pthread_mutex_lock(&txsc_info_cache_mutex);
		memcpy(stats_tx_secy, &my_libnl_status->txsc_info_cache_data.stats.stats_tx_secy, sizeof(t_MKA_stats_transmit_secy));
		memcpy(stats_rx_secy, &my_libnl_status->txsc_info_cache_data.stats.stats_rx_secy, sizeof(t_MKA_stats_receive_secy));
		memcpy(stats_tx_sc, &my_libnl_status->txsc_info_cache_data.stats.stats_tx_sc, sizeof(t_MKA_stats_receive_secy));
		memcpy(stats_rx_sc, &my_libnl_status->txsc_info_cache_data.stats.stats_rx_sc, sizeof(t_MKA_stats_receive_sc));
		pthread_mutex_unlock(&txsc_info_cache_mutex);
	/*
		// These are in: u64 per-SecY stats - macsec_secy_stats_attr
		MKA_LOG_DEBUG2("Packets out untagged  : %u",stats_tx_secy->out_pkts_untagged);
		MKA_LOG_DEBUG2("Packets out too long  : %u",stats_tx_secy->out_pkts_too_long);
		MKA_LOG_DEBUG2("Packets in untagged   : %u",stats_rx_secy->in_pkts_untagged); // Packets without tag, accepted because validateFrames != Strict
		MKA_LOG_DEBUG2("Packets in no tag     : %u",stats_rx_secy->in_pkts_no_tag); // Packets without tag, discarded because validateFrames == Strict
		MKA_LOG_DEBUG2("Packets in bad tag    : %u",stats_rx_secy->in_pkts_bad_tag); // Packets with a bad tag, discarded
		MKA_LOG_DEBUG2("Packets in No SA      : %u",stats_rx_secy->in_pkts_no_sa); // Packets with no SA, accepted because validateFrames != Strict
		MKA_LOG_DEBUG2("Packets in No SA Error: %u",stats_rx_secy->in_pkts_no_sa_error); // Packets with no SA, discarded because validateFrames == Strict
		MKA_LOG_DEBUG2("Packets in Overrun    : %u",stats_rx_secy->in_pkts_overrun); // Packets discarded because of validation/decryption performance limit reached

		// These are in: u64 per-TXSC stats - macsec_txsc_stats_attr
		MKA_LOG_DEBUG2("Octets out encrypted  : %u", stats_tx_secy->out_octets_encrypted);
		MKA_LOG_DEBUG2("Octets out protected  : %u", stats_tx_secy->out_octets_protected);
		MKA_LOG_DEBUG2("Packets out encrypted : %u",stats_tx_sc->out_pkts_encrypted);
		MKA_LOG_DEBUG2("Packets out protected : %u",stats_tx_sc->out_pkts_protected);

		// These are in: u64 per-RXSC stats  - macsec_rxsc_stats_attr
		MKA_LOG_DEBUG2("Octets in validated   : %ld",stats_rx_secy->in_octets_validated);
		MKA_LOG_DEBUG2("Octets in decrypted   : %u",stats_rx_secy->in_octets_decrypted);
		MKA_LOG_DEBUG2("Packets in OK         : %u",stats_rx_sc->in_pkts_ok); // Packets which passed all checks
		MKA_LOG_DEBUG2("Packets in unchecked  : %u",stats_rx_sc->in_pkts_unchecked); // Packets with invalid macsec frame, accepted because validateFrames == Disabled
		MKA_LOG_DEBUG2("Packets in delayed    : %u",stats_rx_sc->in_pkts_delayed); // Packets with pn < minimum, accepted because replay protect is inactive
		MKA_LOG_DEBUG2("Packets in late       : %u",stats_rx_sc->in_pkts_late); // Packets with pn < minimum, discarded because replay protect is active
		MKA_LOG_DEBUG2("Packets in invalid    : %u",stats_rx_sc->in_pkts_invalid); // Packets with invalid macsec frame, accepted because validateFrames == Check
		MKA_LOG_DEBUG2("Packets in not valid  : %u",stats_rx_sc->in_pkts_not_valid); // Packets with invalid macsec frame, discarded because validateFrames == Strict
	*/
	}
    return err;
}
