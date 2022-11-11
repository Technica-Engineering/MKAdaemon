/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_link_monitor.c
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
 * @file        mka_link_monitor.c
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA physical link status monitor
 *
 * @{
 */

/*******************        Includes        *************************/
#include "mka_private.h"
#include <errno.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h> // socket, bind, sendto, recvfrom
#include <sys/ioctl.h> // ioctl
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

//lint -save

/*******************        Defines           ***********************/

/*******************        Types             ***********************/

/*******************        Variables         ***********************/
static int_atomic_t         thread_running = 0;
static pthread_t            thread;
static sint_t               thread_fd;
static int_atomic_t         interface_status[MKA_NUM_BUSES] = {0};
static sem_t                thread_sync;

/*******************        Func. prototypes  ***********************/
static void* mka_link_monitor_thread(void* dummy);
static bool mka_link_monitor_getstatus(sint_t socket, t_MKA_bus bus);
static bool handle_netlink_message(ssize_t status, uint8_t* buf);

/*******************        Func. definition  ***********************/

void mka_link_monitor_start(void)
{
    // thread not running
    if (0 == thread_running) {
        MKA_LOG_DEBUG0("Link monitor: Starting");
        // initialise semaphore
        (void)sem_init(&thread_sync, 0, 0);

        // create thread
        sint_t pthread_result = pthread_create(&thread, NULL, mka_link_monitor_thread, NULL);
        MKA_ASSERT(0 == pthread_result, "Link monitor: Cannot create thread.");

        // wait for thread to complete startup
        (void)sem_wait(&thread_sync);
    }
}

void mka_link_monitor_stop(void)
{
    // thread running
    if (0 != thread_running) {
        MKA_LOG_DEBUG0("Link monitor: Stopping");
        // Apparently there is no reliable mechanism to unblock recvmsg() recvfrom() (!!)
        // just kill the thread using pthread_cancel(),  otherwise the whole process
        // receives the signal, terminating uncleanly, or stopping the shutdown process
        pthread_cancel(thread);
        thread_running = 0;

        (void)shutdown(thread_fd, SHUT_RDWR);
        close(thread_fd);
        
        MKA_ASSERT(0 == pthread_join(thread, NULL), "Link monitor: Cannot join with thread");
        (void)sem_destroy(&thread_sync);
    }
}

void mka_link_monitor_update(void)
{
    t_MKA_bus bus;

    for(bus=0U; bus<MKA_NUM_BUSES; ++bus) {
        MKA_SetPortEnabled(bus, (interface_status[bus] > 0) ? true : false);
    }
}

static bool handle_netlink_message(ssize_t status, uint8_t* buf)
{
    bool status_change = false;
    uint32_t pos = 0U;

    // iterate message elements
    while(pos < (status - sizeof(struct nlmsghdr))) {
        struct nlmsghdr const* const h = (struct nlmsghdr const*)&buf[NLMSG_ALIGN(pos)];

        if ((h->nlmsg_type != RTM_NEWROUTE) && (h->nlmsg_type != RTM_DELROUTE)) {
            struct ifinfomsg const*ifi = (struct ifinfomsg const*) NLMSG_DATA(h);
            char const *ifName = NULL;

            // retrieve interface name from RTA list
            {
                sint_t len = h->nlmsg_len;
                struct rtattr *rta;

                for(rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta=RTA_NEXT(rta, len)) {
                    if ((rta->rta_type <= IFLA_MAX) && (IFLA_IFNAME == rta->rta_type)) {
                        ifName = RTA_DATA(rta);
                    }
                }
            }

            // we've got a physical interface name
            if (NULL != ifName) {
                t_MKA_bus bus;
                for(bus=0U; bus<MKA_NUM_BUSES; ++bus) {
                    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
                    // case this bus is unconfigured
                    if (NULL == cfg->port_name) {
                        // No action

                    } // case this is a different bus
                    else if (0 != strcmp(cfg->port_name, ifName)) {
                        // No action

                    } // physical interface matches mkad bus
                    else {
                        static uint_t const up_flags = IFF_UP | IFF_RUNNING; // Consider interface link up when is configured "UP" and it has physical link.
                        interface_status[bus] = (up_flags == (ifi->ifi_flags & up_flags)) ? 1 : 0;
                        MKA_LOG_DEBUG0("Link monitor: Interface %s is now %s", cfg->port_name, interface_status[bus] ? "UP" : "DOWN");
                        status_change = true;
                        break;
                    }
                }
            }
        }

        pos += NLMSG_ALIGN(h->nlmsg_len);
    }

    return status_change;
}

static bool mka_link_monitor_getstatus(sint_t socket, t_MKA_bus bus)
{
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    struct ifreq ifr;
    bool state = false;

    memset(&ifr, 0, sizeof(ifr));

    // bus not configured
    if (NULL == cfg->port_name) {
        // no action

    } // no name?
    else if (NULL == strncpy(ifr.ifr_name, cfg->port_name, IFNAMSIZ-1)) {
        // no action

    } // cannot get interface status (permissions?)
    else if (0 != ioctl(socket, SIOCGIFFLAGS, &ifr)) {
        MKA_LOG_ERROR("Link monitor: %i cannot get status of interface (ioctl/SIOCGIFFLAGS error %s)!", bus, strerror(errno));

    } // status retrieved
    else {
        static uint_t const up_flags = IFF_UP | IFF_RUNNING; // Consider interface link up when is configured "UP" and it has physical link.
        state = (up_flags == (ifr.ifr_flags & up_flags));
    }

    return state;
}


static void* mka_link_monitor_thread(void* dummy)
{
    struct sockaddr_nl local;
    struct msghdr msg;
    static uint8_t buf[8192];

    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    // Perform socket initialisation
    {
        thread_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        MKA_ASSERT(thread_fd >= 0, "Link monitor: Failed to create netlink socket! (missing capabilities/permissions?)");

        memset(&local, 0, sizeof(local));
        local.nl_family = AF_NETLINK;
        local.nl_groups = RTMGRP_LINK;
        local.nl_pid = getpid();

        sint_t bind_result = bind(thread_fd, (struct sockaddr*)&local, sizeof(local));
        MKA_ASSERT(bind_result >= 0, "Link monitor: Cannot bind netlink socket.");

        msg.msg_name = &local;                  // local address
        msg.msg_namelen = sizeof(local);        // address size
        msg.msg_iov = &iov;                     // io vector
        msg.msg_iovlen = 1;                     // io size
    }   

    // Perform initial check of current interface status
    // this is just for the initial state; we will receive events for link changes afterwards.
    {
        t_MKA_bus bus;
        for(bus=0U; bus<MKA_NUM_BUSES; ++bus) {
            if (mka_link_monitor_getstatus(thread_fd, bus)) {
                interface_status[bus] = true;
                mka_main_loop_wakeup();
            }
        }

    }

    // Notify startup completed
    thread_running = 1;
    (void)sem_post(&thread_sync);

    // Receive interface link events
    while(thread_running > 0) {
        ssize_t status = recvmsg(thread_fd, &msg, 0);

        // case we've got an interruption of recvmsg() when cleaning up
        if (status <= 0) {
            MKA_ASSERT(EINTR == errno, "Link monitor: Unexpected response of recvmsg from netlink socket");

        } // case length doesn't match what we expect
        else if (msg.msg_namelen != sizeof(local)) {
            MKA_ASSERT(msg.msg_namelen == sizeof(local), "Link monitor: Unexpected message length from netlink");

        } // case no interface handled by mkad has changed status
        else if (!handle_netlink_message(status, buf)) {
            /* No action */

        } // case some interface changed status
        else {
            mka_main_loop_wakeup(); // wake up main thread to attend this event
        }
    }

    // cleanup
    close(thread_fd);
    thread_running = 0;

    (void)sem_post(&thread_sync);

    return NULL;
}

//lint -restore

/** @} */




