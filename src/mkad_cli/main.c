/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: main.c
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
 * @file        main.c
 * @version     1.0.0
 * @author      Jordi Auge
 * @brief       MKAD Dbus Client
 *
 * @{
 */

/*******************        Includes        *************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <gio/gio.h>
#include <libxml/parser.h>
#include <net/if.h>
#include "main.h"
#include "gdbus-mkad-generated.h"

/*******************        Variables         ***********************/


/*******************        Func. definition  ***********************/

const char* get_dbus_introspect_xml(){
    GError *error;
    GDBusProxy *introspection_proxy;
    gpointer data;


    error = NULL;
    introspection_proxy = g_dbus_proxy_new_for_bus_sync (
                                        G_BUS_TYPE_SYSTEM,
                                        (GDBusProxyFlags)G_DBUS_CALL_FLAGS_NONE,
                                        NULL, /* GDBusInterfaceInfo */
                                        "de.technica_engineering.mkad", /* your service name */
                                        "/de/technica_engineering/mkad", /* your root object */
                                        "org.freedesktop.DBus.Introspectable",
                                        NULL, /* GCancellable */
                                        &error);
    if (error != NULL){
        printf("Error: Could not connect to dbus\n");
        exit(1);
    }
    error = NULL;
    data = g_dbus_proxy_call_sync(introspection_proxy,
                    "Introspect", 
                    NULL,
                    G_DBUS_CALL_FLAGS_NONE,
                    -1, 
                    NULL,
                    &error);
    if (error != NULL){
        printf("Error: Could not connect mkad daemon via dbus. Is it running and connected to dbus?\n");
        exit(1);
    }  
    
    const char *xml_str = g_variant_get_string(g_variant_get_child_value(data,0),NULL);
    g_object_unref(introspection_proxy);

    return xml_str;
}

mkadBUS* get_mkad_proxy(char *active_bus){
    GError *error = NULL;
    mkadBUS *mkad_proxy;
    char intf_name[IFNAMSIZ+35];
    strcpy(intf_name, "/de/technica_engineering/mkad/");
    strncat(intf_name, active_bus, IFNAMSIZ+1);
    strncat(intf_name, "/BUS", 5);
    mkad_proxy = mkad_bus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SYSTEM,
        G_DBUS_PROXY_FLAGS_NONE,
        "de.technica_engineering.mkad",
        intf_name,
        NULL, /* GCancellable */
        &error       
    );
    return mkad_proxy;
}

void set_bus_enabled(mkadBUS* mkad_proxy, char* set_enabled){
    gboolean out_result;
    GError *error = NULL;
    bool enabled = false;
    if (strcmp(set_enabled,"0")==0){
        printf("Disable\n");
        enabled = false;
    } else if (strcmp(set_enabled,"1")==0){
        printf("Enable\n");
        enabled = true;
    } else {
        printf("Error: Set enabled must be passed value 0 or 1\n");
        exit(0);
    }
    mkad_bus_call_set_enable_sync (
        mkad_proxy,
        enabled,
        &out_result,
        NULL, /* GCancellable */
        &error
    );
    printf("\n");
}

void print_bus_info(mkadBUS* mkad_proxy){
    GVariant *bus_info;
    bus_info = mkad_bus_get_bus_info(mkad_proxy);
    GVariant *bus_status_code = g_variant_get_child_value(bus_info,0);
    GVariant *bus_status_string = g_variant_get_child_value(bus_info,1);
    printf("    Bus status: %i - %s\n", g_variant_get_uint32(bus_status_code), g_variant_get_string(bus_status_string, NULL));
    GVariant *peer_sci = g_variant_get_child_value(bus_info,2);
    printf("    Peer SCI: %s\n", g_variant_get_string(peer_sci, NULL));
    printf("\n");
    g_variant_unref(bus_status_code);
    g_variant_unref(bus_status_string);
    g_variant_unref(peer_sci);
    g_variant_unref(bus_info);
}

void print_bus_stats(mkadBUS* mkad_proxy){
    GVariant *bus_stats;
    GVariant *stat_item;
    GVariant *stat_name;
    GVariant *stat_value;
    bus_stats = mkad_bus_get_macsec_stats(mkad_proxy);
    for (long unsigned int i=0; i<g_variant_n_children(bus_stats);i++){
        stat_item = g_variant_get_child_value(bus_stats,i);
        stat_name = g_variant_get_child_value(stat_item,0);
        stat_value = g_variant_get_child_value(stat_item,1);
        printf("    %s: %lu\n", g_variant_get_string(stat_name, NULL), g_variant_get_uint64(stat_value));
        g_variant_unref(stat_name);
        g_variant_unref(stat_value);
        g_variant_unref(stat_item);
    }
    printf("\n");
}

int main( int argc, char *argv[] )
{
    char* selected_bus = NULL;
    bool show_stats = false;
    char* set_enabled = NULL;
    bool show_businfo = false;
    bool something_requested = false;
    int option;

    for (;;) {
        option = getopt(argc, argv,
                "hb:e:si");
        if (option < 0)
            break;
        switch (option) {
            case 'b':
                selected_bus = optarg;
                break;
            case 'e':
                set_enabled = optarg;
                something_requested = true;
                break;
            case 's':
                show_stats = true;
                something_requested = true;
                break;
            case 'i':
                show_businfo = true;
                something_requested = true;
                break;
            case 'h':
            default:
                print_usage();
                exit(EXIT_SUCCESS);
                break;
        }
    }

    if (something_requested == false){
        printf("Error: No action requested\n");
        printf("\n");
        print_usage();
        exit(0);
    }

    // Call the dbus introspect interface to enumerate which interfaces there are
    const char *xml_str = get_dbus_introspect_xml();
    
    

    // The answer is an XML document, we need to parse it
    xmlDoc         *document;
    xmlNode        *root, *first_child, *node;
    document = xmlReadMemory(xml_str, strlen(xml_str), "noname.xml", NULL, 0);
    root = xmlDocGetRootElement(document);
    int n_buses = 0;
    char active_bus[IFNAMSIZ+1] = {0};
    bool bus_selected = false;
    // count how many buses are available in the daemon
    
    first_child = root->children;
    for (node = first_child; node; node = node->next) {
        if (node->type == 1){
            n_buses++;
        }
    }

    if ((n_buses > 1) && (selected_bus == NULL)){
        printf("There is more than 1 bus available, so you must specify which one.\n");
        printf("Buses available:\n");
        first_child = root->children;
        for (node = first_child; node; node = node->next) {
            if (node->type == 1){
                fprintf(stdout, "\t%s\n", xmlGetProp(node,(const unsigned char *)"name"));
            }
        }
        exit(0);
    }
    if (n_buses == 0){
        printf("No mkad bus is available, make sure mkad is running and has dbus enabled\n");
        exit(0);
    }
    if (n_buses == 1){
        first_child = root->children;
        for (node = first_child; node; node = node->next) {
            if (node->type == 1){
                if ((selected_bus != NULL) && (strcmp(selected_bus,(char *)xmlGetProp(node,(const unsigned char *)"name")) != 0)){
                    printf("Requested bus is not available\n");
                    exit(1);
                }
                strncpy(active_bus, (char *)xmlGetProp(node,(const unsigned char *)"name"), IFNAMSIZ);
            }
        }
    } else { // n_buses >1
        first_child = root->children;
        for (node = first_child; node; node = node->next) {
            if (node->type == 1){
                if (strcmp(selected_bus,(char *) xmlGetProp(node,(const unsigned char *)"name")) == 0){
                    strncpy(active_bus, (char *) xmlGetProp(node,(const unsigned char *)"name"), IFNAMSIZ);
                    bus_selected = true;
                }
                
            }
        }
        if (bus_selected == false){
            printf("Requested bus is not available\n");
            exit(1);
        }
    }
    

    // We now know which bus we want to operate on, let's create a proxy for all further operations
    mkadBUS *mkad_proxy = get_mkad_proxy(active_bus);

    
    // Operation -s: Set enabled/disabled
    if (set_enabled != NULL){
        printf("Setting enabling state of bus %s to: ", active_bus);
        set_bus_enabled(mkad_proxy, set_enabled);
    }

    // Operation -i: Get bus info
    if (show_businfo == true){
        printf("Bus Info for bus %s:\n", active_bus);
        print_bus_info(mkad_proxy);
    }

    // Operation -s: Get statistics
    if (show_stats == true){
        printf("Statistics for bus %s:\n", active_bus);
        print_bus_stats(mkad_proxy);
    }
    exit(0);
}

void print_usage(){
    printf("Usage: mkad_cli\n");
    printf("\n");
    printf("    -e [0/1] - Set bus enabled or disabled\n");
    printf("\n");
    printf("    -s - Get statistics\n");
    printf("\n");
    printf("    -i - Get bus info\n");
    printf("\n");
    printf("    -b <bus name> - Select which bus you want to use, only necessary if there is more tha one.\n");
    printf("\n");
    printf("    -h    - Help\n");
    printf("            Print this message and exit\n");
}
