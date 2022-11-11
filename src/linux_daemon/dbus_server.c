/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: dbus_server.c
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

#include "gdbus-mkad-generated.h"
#include "mka_private.h"
#include "mka_types.h"
#include "dbus_server.h"
#include "dbus_event_action.h"
#include <net/if.h>

pthread_t dbus_thread;
GMainLoop *loop;
guint id;
char bus_names[10][IFNAMSIZ+1] = {0};
mkadBUS* interfaces[10];
int num_buses_enabled = 0;

static gboolean
on_set_enable (mkadBUS          *bus,
                GDBusMethodInvocation  *invocation,
                gboolean                enabled,
                gpointer                user_data)
{
  int n_bus = -1;
  for (int i=0;i<num_buses_enabled;i++){
    if (bus == interfaces[i]) n_bus = i;
  }
  if (n_bus == -1) {
    MKA_LOG_WARNING("Got a request to enable/disable a nonexisting bus");
    return false;
    }
  MKA_LOG_DEBUG1("Dbus method set enabled called on bus %d: %d", n_bus, enabled);
  MKA_SetEnable(n_bus, enabled);
  mkad_bus_complete_set_enable(bus,invocation,true);
  return true;
}

void dbus_update_statistics(t_MKA_bus bus, t_MKA_stats_transmit_secy * stats_tx_secy, t_MKA_stats_receive_secy * stats_rx_secy, t_MKA_stats_transmit_sc * stats_tx_sc, t_MKA_stats_receive_sc * stats_rx_sc){
  MKA_LOG_DEBUG3("Dbus updating statistics");
  
  // How many keys (statistics) we want to send
  const int n_stats = 19;

  GVariant *stats[n_stats];
  GVariant **tuples[n_stats];

  // Each stat struct has 2 members (key and value)
  tuples[0] = g_new(GVariant *, 2);
  tuples[0][0] = g_variant_new_string("out_pkts_untagged");
  tuples[0][1] = g_variant_new_uint64(stats_tx_secy->out_pkts_untagged);
  stats[0] = g_variant_new_tuple(tuples[0], 2);

  tuples[1] = g_new(GVariant *, 2);
  tuples[1][0] = g_variant_new_string("out_pkts_too_long");
  tuples[1][1] = g_variant_new_uint64(stats_tx_secy->out_pkts_too_long);
  stats[1] = g_variant_new_tuple(tuples[1], 2);

  tuples[2] = g_new(GVariant *, 2);
  tuples[2][0] = g_variant_new_string("out_octets_protected");
  tuples[2][1] = g_variant_new_uint64(stats_tx_secy->out_octets_protected);
  stats[2] = g_variant_new_tuple(tuples[2], 2);

  tuples[3] = g_new(GVariant *, 2);
  tuples[3][0] = g_variant_new_string("out_octets_encrypted");
  tuples[3][1] = g_variant_new_uint64(stats_tx_secy->out_octets_encrypted);
  stats[3] = g_variant_new_tuple(tuples[3], 2);

  tuples[4] = g_new(GVariant *, 2);
  tuples[4][0] = g_variant_new_string("in_pkts_untagged");
  tuples[4][1] = g_variant_new_uint64(stats_rx_secy->in_pkts_untagged);
  stats[4] = g_variant_new_tuple(tuples[4], 2);

  tuples[5] = g_new(GVariant *, 2);
  tuples[5][0] = g_variant_new_string("in_pkts_no_tag");
  tuples[5][1] = g_variant_new_uint64(stats_rx_secy->in_pkts_no_tag);
  stats[5] = g_variant_new_tuple(tuples[5], 2);

  tuples[6] = g_new(GVariant *, 2);
  tuples[6][0] = g_variant_new_string("in_pkts_bad_tag");
  tuples[6][1] = g_variant_new_uint64(stats_rx_secy->in_pkts_bad_tag);
  stats[6] = g_variant_new_tuple(tuples[6], 2);

  tuples[7] = g_new(GVariant *, 2);
  tuples[7][0] = g_variant_new_string("in_pkts_no_sa");
  tuples[7][1] = g_variant_new_uint64(stats_rx_secy->in_pkts_no_sa);
  stats[7] = g_variant_new_tuple(tuples[7], 2);

  tuples[8] = g_new(GVariant *, 2);
  tuples[8][0] = g_variant_new_string("in_pkts_overrun");
  tuples[8][1] = g_variant_new_uint64(stats_rx_secy->in_pkts_overrun);
  stats[8] = g_variant_new_tuple(tuples[8], 2);

  tuples[9] = g_new(GVariant *, 2);
  tuples[9][0] = g_variant_new_string("in_octets_validated");
  tuples[9][1] = g_variant_new_uint64(stats_rx_secy->in_octets_validated);
  stats[9] = g_variant_new_tuple(tuples[9], 2);

  tuples[10] = g_new(GVariant *, 2);
  tuples[10][0] = g_variant_new_string("in_octets_decrypted");
  tuples[10][1] = g_variant_new_uint64(stats_rx_secy->in_octets_decrypted);
  stats[10] = g_variant_new_tuple(tuples[10], 2);

  tuples[11] = g_new(GVariant *, 2);
  tuples[11][0] = g_variant_new_string("out_pkts_protected");
  tuples[11][1] = g_variant_new_uint64(stats_tx_sc->out_pkts_protected);
  stats[11] = g_variant_new_tuple(tuples[11], 2);

  tuples[12] = g_new(GVariant *, 2);
  tuples[12][0] = g_variant_new_string("out_pkts_encrypted");
  tuples[12][1] = g_variant_new_uint64(stats_tx_sc->out_pkts_encrypted);
  stats[12] = g_variant_new_tuple(tuples[12], 2);

  tuples[13] = g_new(GVariant *, 2);
  tuples[13][0] = g_variant_new_string("in_pkts_ok");
  tuples[13][1] = g_variant_new_uint64(stats_rx_sc->in_pkts_ok);
  stats[13] = g_variant_new_tuple(tuples[13], 2);

  tuples[14] = g_new(GVariant *, 2);
  tuples[14][0] = g_variant_new_string("in_pkts_unchecked");
  tuples[14][1] = g_variant_new_uint64(stats_rx_sc->in_pkts_unchecked);
  stats[14] = g_variant_new_tuple(tuples[14], 2);

  tuples[15] = g_new(GVariant *, 2);
  tuples[15][0] = g_variant_new_string("in_pkts_delayed");
  tuples[15][1] = g_variant_new_uint64(stats_rx_sc->in_pkts_delayed);
  stats[15] = g_variant_new_tuple(tuples[15], 2);

  tuples[16] = g_new(GVariant *, 2);
  tuples[16][0] = g_variant_new_string("in_pkts_late");
  tuples[16][1] = g_variant_new_uint64(stats_rx_sc->in_pkts_late);
  stats[16] = g_variant_new_tuple(tuples[16], 2);

  tuples[17] = g_new(GVariant *, 2);
  tuples[17][0] = g_variant_new_string("in_pkts_invalid");
  tuples[17][1] = g_variant_new_uint64(stats_rx_sc->in_pkts_invalid);
  stats[17] = g_variant_new_tuple(tuples[17], 2);

  tuples[18] = g_new(GVariant *, 2);
  tuples[18][0] = g_variant_new_string("in_pkts_not_valid");
  tuples[18][1] = g_variant_new_uint64(stats_rx_sc->in_pkts_not_valid);
  stats[18] = g_variant_new_tuple(tuples[18], 2);

  GVariant *gstats = g_variant_new_array (NULL, stats, n_stats);

  mkad_bus_set_macsec_stats(interfaces[bus], gstats);

  // Free created objects
  for (int i=0; i<n_stats;i++){
    g_free(tuples[i]);
  }
}

void dbus_notify_event(t_MKA_bus bus, t_MKA_event event){
  
  GVariant *event_tuple[2];
  event_tuple[0] = g_variant_new_uint32((uint32_t)event);
  switch(event){
    case MKA_EVENT_PORT_VALID:
      event_tuple[1] = g_variant_new_string("Port valid");
      break;
    case MKA_EVENT_PORT_NOT_VALID:
      event_tuple[1] = g_variant_new_string("Port not valid");
      break;
    case MKA_EVENT_LINKUP:
      event_tuple[1] = g_variant_new_string("Link up");
      break;
    case MKA_EVENT_INIT:
    default:
      event_tuple[1] = g_variant_new_string("Unknown status");
      break;
  }
  GVariant *g_event = g_variant_new_tuple(event_tuple,2);
  //MKA_LOG_DEBUG1("Type string is %s",g_variant_get_type_string(g_event));
  mkad_bus_set_event_action(interfaces[bus], g_event);
}

void dbus_update_status(){
  MKA_LOG_DEBUG3("Dbus updating status");
  bool status;
  // Structures for BusInfo
  t_MKA_bus_info mka_bus_info;
  GVariant *bus_info_tuple[3];
  char peer_sci_str[21];
  GVariant *bus_info;


  for (int bus=0;bus<num_buses_enabled;bus++){
    // Update is_enabled
    MKA_GetEnable(bus, &status);
    mkad_bus_set_is_enabled (interfaces[bus], status);

    // Update BusInfo
    MKA_GetBusInfo(bus, &mka_bus_info);
    
    bus_info_tuple[0] = g_variant_new_uint32((int)mka_bus_info.status);
    switch(mka_bus_info.status){
      case 0:
        bus_info_tuple[1] = g_variant_new_string("Macsec is running");
        break;
      case 1:
        bus_info_tuple[1] = g_variant_new_string("Waiting for Link");
        break;
      case 2:
        bus_info_tuple[1] = g_variant_new_string("Waiting for Peer MKA");
        break;
      case 3:
        bus_info_tuple[1] = g_variant_new_string("MKA in progress");
        break;
      case 6:
        bus_info_tuple[1] = g_variant_new_string("Unknown peer (remote ICVs are invalid)");
        break;
      case 7:
        bus_info_tuple[1] = g_variant_new_string("Peer Certificate validation failed");
        break;
      default:
        bus_info_tuple[1] = g_variant_new_string("Unknown status");
        break;
    }
    
    
    for (int i=0;i<6;i++){
      snprintf(peer_sci_str+(3*i), 4, "%02x:", mka_bus_info.peer_sci.addr[i]);
    }
    snprintf(peer_sci_str+15, 6, "%u", mka_bus_info.peer_sci.port);
    bus_info_tuple[2] = g_variant_new_string(peer_sci_str);
    bus_info = g_variant_new_tuple(bus_info_tuple,3);
    //MKA_LOG_DEBUG1("Type string is %s",g_variant_get_type_string(bus_info));
    mkad_bus_set_bus_info(interfaces[bus], bus_info);
  }
}

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
    MKA_LOG_DEBUG1 ("Acquired the bus %s", name);
    GError *error = NULL;
    t_MKA_bus bus;
    
    char intf_name[IFNAMSIZ+35];
    MKA_LOG_DEBUG1("Num buses enabled: %d", num_buses_enabled);
    for(bus=0U; bus<num_buses_enabled; bus++) {
      MKA_LOG_DEBUG1("Creating interface for bus %d", bus);
      interfaces[bus] = mkad_bus_skeleton_new();

      g_signal_connect(interfaces[bus], "handle_set_enable",
                        G_CALLBACK(on_set_enable),
                        NULL);

      error = NULL;
      strcpy(intf_name, "/de/technica_engineering/mkad/");
      char **busname_split = g_strsplit(bus_names[bus], ".", -1);
      char *busname = g_strjoinv("", busname_split);
      g_strfreev(busname_split);
      //strncat(intf_name, g_dbus_escape_object_path(busname), IFNAMSIZ); // g_dbus_escape object is only available on glib >=2.68
      strncat(intf_name, busname, IFNAMSIZ);
      strcat(intf_name, "/BUS");
      g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (interfaces[bus]), connection, intf_name, &error);
    }
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
  MKA_LOG_DEBUG1 ("Acquired the name %s", name);
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
  MKA_LOG_DEBUG1 ("Lost the name %s", name);
}

static void* dbus_server_thread(void* dbus_arg){
    MKA_LOG_DEBUG1("Starting Dbus server");
    // Not necessary if glib >= 2.32
    // Ubuntu 20.04 uses 2.56
    // S32g yocto uses 2.64
    // Ubuntu 22.04 uses 2.72
    //g_type_init ();

    loop = g_main_loop_new (NULL, FALSE);

    id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
                        "de.technica_engineering.mkad",
                        G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT |
                        G_BUS_NAME_OWNER_FLAGS_REPLACE,
                        on_bus_acquired,
                        on_name_acquired,
                        on_name_lost,
                        loop,
                        NULL);

    g_main_loop_run (loop);

    
    return MKA_OK;
}


t_MKA_result dbus_server_init(t_MKA_config const* cfg){
  t_MKA_bus bus;
  for(bus=0U; bus<MKA_NUM_BUSES_CONFIGURED; ++bus) {
    MKA_LOG_DEBUG1("Processing bus %d", (int)bus);
    strncat(bus_names[bus], cfg->bus_config[bus].controlled_port_name, IFNAMSIZ);
    num_buses_enabled++;
  }

  sint_t pthread_result = pthread_create(&dbus_thread, NULL, dbus_server_thread, NULL);
  if (pthread_result != 0){
    MKA_LOG_ERROR("Cannot create Dbus thread.");
    return MKA_NOT_OK;
  }
  return MKA_OK;  
}


t_MKA_result dbus_server_stop(){
    g_bus_unown_name (id);
    g_main_loop_unref (loop);
    return MKA_OK;
}
