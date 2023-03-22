/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_l2_linux.c
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
******************************************************************************/

/*****************************************************************************
 * @file        mka_l2_linux.c
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       Linux layer 2 communication access
 *
 * @{
 */

/*******************        Includes        *************************/
#include <sys/types.h>
#include <sys/socket.h> // socket, bind, sendto, recvfrom
#include <errno.h> // return codes
#include <net/if.h> // ifreq ioctl
#include <linux/if_ether.h>
#include <linux/if_packet.h> // sockaddr_ll
#include <sys/ioctl.h> // ioctl
#include <unistd.h> // close
#include <pthread.h>
#include "mka_private.h"

/*******************        Defines           ***********************/
#define MKA_RX_FIFO_LEN         100U

/* Macros below implement RX packet FIFO */
/* Initialise rx-packet FIFO */
#define RX_PFIFO_INIT(pDescriptor) \
    /*lint -e{9087} Unavoidable pointer cast */ \
    fifo_init(&pDescriptor->rx_fifo, (uint16_t)MKA_RX_FIFO_LEN*(uint16_t)sizeof(t_mka_l2_frame*), (void*)(&pDescriptor->rx_packets[0]))

/* Reset rx-packet FIFO */
#define RX_PFIFO_RESET(pDescriptor) \
    fifo_reset(&pDescriptor->rx_fifo)

/* Push element to rx-packet FIFO */
#define RX_PFIFO_PUSH(pDescriptor, pEntry) \
    /*lint -e{9087} Unavoidable pointer cast */ \
    fifo_push(&pDescriptor->rx_fifo, (void const*)pEntry, (uint16_t)sizeof(t_mka_l2_frame*))

/* Pop element from rx-packet FIFO */
#define RX_PFIFO_POP(pDescriptor, pEntry) \
    /*lint -e{9087} Unavoidable pointer cast */ \
    fifo_pop(&pDescriptor->rx_fifo, (void*)pEntry, (uint16_t)sizeof(t_mka_l2_frame*))

/* Get whether rx-packet FIFO is empty */
#define RX_PFIFO_EMPTY(pDescriptor) \
    /*lint -e{9087} Unavoidable pointer cast */ \
    fifo_empty(&pDescriptor->rx_fifo)


/*******************        Types             ***********************/
typedef struct {
    uint8_t             payload[1500U];
    uint32_t            size;
} t_mka_l2_frame;

typedef struct {
    bool volatile               enabled;
    uint16_t                    rx_protocol;
    sint_t                      socket;         // Linux socket
    sint_t                      if_index;       // Linux interface index
    uint8_t                     hw_addr[MKA_L2_ADDR_SIZE]; // own MAC

    // Reception thread
    bool volatile               rx_thread_run;
    pthread_t                   rx_thread;
    pthread_mutex_t             rx_fifo_mutex;
    t_fifo                      rx_fifo;
    t_mka_l2_frame*             rx_packets[MKA_RX_FIFO_LEN];
} t_mka_l2_descriptor;

/*******************        Variables         ***********************/
static t_mka_l2_descriptor  mka_l2[MKA_NUM_BUSES] = {{false}};

/*******************        Func. prototypes  ***********************/

static void* mka_l2_receive_thread(void* bus_arg);
static t_MKA_result set_multicast_reception(bool enable, const char* if_name, int socket);


t_MKA_result MKA_l2_init(t_MKA_bus bus, uint16_t protocol)
{
    t_mka_l2_descriptor *const l2 = &mka_l2[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];
    struct ifreq if_req; // used in IOCTL to request linux interface index
    t_MKA_result result = MKA_OK;

    l2->rx_protocol = protocol;

    if (l2->enabled) {
        MKA_LOG_WARNING("L2/%i attempt to initialise an already initialised interface!", bus);
        result = MKA_NOT_OK;
    }

    // Create socket descriptor
    l2->socket = socket(
        /* domain   */ AF_PACKET,
        /* type     */ SOCK_RAW,
        /* protocol */ MKA_HTONS(protocol)
    );
    if (l2->socket < 0) {
        MKA_LOG_ERROR("L2/%i cannot create a new raw socket! (missing capabilities/permission? try 'setcap cap_net_raw,cap_net_admin=eip program')", bus);
        result = MKA_NOT_OK;
    }

    // Get reference to linux interface
    if (MKA_OK == result) {
        (void)memset(&if_req, 0, sizeof(if_req));
        (void)strncpy(if_req.ifr_name, cfg->port_name, sizeof(if_req.ifr_name)-1);
        if (ioctl(  /* fd   */ l2->socket,
                    /* req  */ SIOCGIFINDEX,
                    /* data */ &if_req          ) < 0) {
            MKA_LOG_ERROR("L2/%i cannot find interface '%s' (does it exist?)", bus, cfg->port_name);
            (void)close(l2->socket);
            result = MKA_NOT_OK;
        }
        else {
            l2->if_index = if_req.ifr_ifindex;
        }
    }

    // Get hardware address
    if (MKA_OK == result) {
        if (ioctl(  /* fd   */ l2->socket,
                    /* req  */ SIOCGIFHWADDR,
                    /* data */ &if_req          ) < 0) {
            MKA_LOG_ERROR("L2/%i cannot get MAC of interface '%s'", bus, cfg->port_name);
            (void)close(l2->socket);
            result = MKA_NOT_OK;
        }
        else {
            (void)memcpy(&l2->hw_addr[0], if_req.ifr_hwaddr.sa_data, MKA_L2_ADDR_SIZE);
        }
    }

    // Bind this socket to linux interface
    if (MKA_OK == result) {
        struct sockaddr_ll ll;
        memset(&ll, 0, sizeof(ll));
        ll.sll_family = AF_PACKET;
        ll.sll_ifindex = l2->if_index;
        ll.sll_protocol = MKA_HTONS(l2->rx_protocol);
        if (bind(   /* fd   */ l2->socket,
                    /* addr */ (struct sockaddr*) &ll,
                    /* alen */ sizeof(ll)       ) < 0) {
            MKA_LOG_ERROR("L2/%i cannot bind socket to interface '%s'", bus, cfg->port_name);
            (void)close(l2->socket);
            result = MKA_NOT_OK;
        }
    }

    // Enable reception of broadcast packets
    if (MKA_OK == result) {
      result = set_multicast_reception(true, cfg->port_name, l2->socket);
    }

    // Create thread
    if (MKA_OK == result) {
        l2->rx_thread_run = true;
        pthread_mutex_init(&l2->rx_fifo_mutex, NULL);
        RX_PFIFO_INIT(l2);
        sint_t pthread_result = pthread_create(&l2->rx_thread, NULL, mka_l2_receive_thread, (void *)l2);
        MKA_ASSERT(0 == pthread_result, "Cannot create thread.");
    }

    l2->enabled = (bool)(MKA_OK == result);

    return result;
}

void MKA_l2_deinit(t_MKA_bus bus)
{
    t_mka_l2_descriptor *const l2 = &mka_l2[bus];
    t_MKA_bus_config const*const cfg = &MKA_active_buses_config[bus];

    if (!l2->enabled) {
        MKA_LOG_WARNING("L2/%i attempt to deinitialise a non-initialised interface!", bus);

    }
    else {
        t_mka_l2_frame *frame;
        uint32_t max_loops = MKA_RX_FIFO_LEN;

        if (l2->rx_thread_run) {
            l2->rx_thread_run = false;
            MKA_ASSERT(0 == pthread_join(l2->rx_thread, NULL), "L2: Cannot join with reception thread");
        }

        while(RX_PFIFO_POP(l2, &frame) && (max_loops > 0U)) {
            MKA_LOG_DEBUG3("Releasing pending RX frame %p", frame);
            free(frame);
            --max_loops;
        }
        RX_PFIFO_RESET(l2);

        if (set_multicast_reception(false, cfg->port_name, l2->socket) != MKA_OK) {
            MKA_LOG_WARNING("Failed to unsubscribe to broadcast packets");
        }

        (void)close(l2->socket);
        (void)memset(l2, 0, sizeof(*l2));
    }
}

// Enable or disable reception of multicast packets, necessary to receive MKA
// packets, since their destination is a multicast address, and not our MAC
static t_MKA_result set_multicast_reception(bool enable, const char* if_name, int socket)
{
    struct packet_mreq mreq;
    int action;
    action = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = if_nametoindex(if_name);
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = ETH_ALEN;
    u8 pae_group_addr[ETH_ALEN] = {0x01,0x80,0xc2,0x00,0x00,0x03};
    memcpy(mreq.mr_address, &pae_group_addr, ETH_ALEN);
    if (setsockopt(socket, SOL_PACKET, action,
                &mreq, sizeof(mreq)) < 0) {
        MKA_LOG_ERROR("setsockopt: %s", strerror(errno));
        return MKA_NOT_OK;
    }
    return MKA_OK;
}

static void* mka_l2_receive_thread(void* bus_arg)
{
    t_mka_l2_descriptor *const l2 = (t_mka_l2_descriptor *)bus_arg;
    t_mka_l2_frame *frame = malloc(sizeof(t_mka_l2_frame));
    ssize_t rx_result;
    bool push_result;
    struct sockaddr_ll ll;
    socklen_t ll_len = 0U;

    while(l2->rx_thread_run) {
        (void)memset(&ll, 0, sizeof(ll));

        rx_result = recvfrom(
            /* sockfd   */ l2->socket,
            /* buf      */ frame->payload,
            /* len      */ sizeof(frame->payload),
            /* flags    */ 0,
            /* src_addr */ (struct sockaddr*)&ll,
            /* addrlen  */ &ll_len
        );

        MKA_ASSERT(rx_result >= 0, "L2 error when reading from socket");
        frame->size = rx_result;

        MKA_ASSERT(0 == pthread_mutex_lock(&l2->rx_fifo_mutex), "L2 cannot lock mutex from RX thread");
        push_result = RX_PFIFO_PUSH(l2, &frame);
        MKA_ASSERT(0 == pthread_mutex_unlock(&l2->rx_fifo_mutex), "L2 cannot unlock mutex from RX thread");

        if (push_result) {
            MKA_LOG_DEBUG3("Received L2 frame frame %p", frame);
            frame = malloc(sizeof(t_mka_l2_frame));
            mka_main_loop_wakeup();
        }
    }

    free(frame);

    return NULL;
}

t_MKA_result MKA_l2_receive(t_MKA_bus bus, uint8_t *packet, uint32_t *len)
{
    t_mka_l2_descriptor *const l2 = &mka_l2[bus];
    t_MKA_result result = MKA_NOT_OK;

    if (!l2->enabled) {
        MKA_LOG_WARNING("L2/%i attempt to receive via non-initialised interface!", bus);
    }
    else {
        t_mka_l2_frame *frame;
        MKA_ASSERT(0 == pthread_mutex_lock(&l2->rx_fifo_mutex), "L2 cannot lock mutex from RX thread");
        bool const is_packet_pending = RX_PFIFO_POP(l2, &frame);
        MKA_ASSERT(0 == pthread_mutex_unlock(&l2->rx_fifo_mutex), "L2 cannot unlock mutex from RX thread");
        bool const packet_fits = is_packet_pending && (frame->size <= *len);

        // packet pending and fits the buffer
        if (packet_fits) {
            (void)memcpy(packet, frame->payload, frame->size);
            *len = frame->size;
            free(frame);
            result = MKA_OK;

        } // Case packet does not fit
        else if (is_packet_pending) {
            MKA_LOG_WARNING("ERROR: Received packet that does not fit MKA buffer, dropping packet.");
            free(frame);

        } // No packet pending
        else {
            // No action
        }

        // Case RX FIFO not empty
        if (!RX_PFIFO_EMPTY(l2)) {
            // chain execution of additional ticks until there are no more frames
            mka_main_loop_wakeup();
        }
    }

    return result;
}

t_MKA_result MKA_l2_transmit(t_MKA_bus bus, uint8_t const*packet, uint32_t len)
{
    t_MKA_l2_ether_header const*const ethhdr = (t_MKA_l2_ether_header const*)packet;
    t_mka_l2_descriptor const*const l2 = &mka_l2[bus];
    t_MKA_result result = MKA_OK;

    if (!l2->enabled) {
        MKA_LOG_WARNING("L2/%i attempt to transmit via non-initialised interface!", bus);
        result = MKA_NOT_OK;
    }
    else {
        struct sockaddr_ll ll;
        (void)memset(&ll, 0, sizeof(ll));
        ll.sll_family = AF_PACKET;
        ll.sll_ifindex = l2->if_index;
        ll.sll_protocol = ethhdr->type;
        ll.sll_halen = MKA_L2_ADDR_SIZE;
        (void)memcpy(&ll.sll_addr[0], &ethhdr->dst[0], MKA_L2_ADDR_SIZE);

        ssize_t tx_result = sendto(
            /* sockfd   */ l2->socket,
            /* buf      */ packet,
            /* len      */ (size_t)len,
            /* flags    */ 0,
            /* dstaddr  */ (struct sockaddr const*)&ll,
            /* addrlen  */ sizeof(ll)
        );
        if (tx_result < 0) {
            MKA_LOG_ERROR("L2/%i cannot transmit packet! (%i: %s)", bus, errno, strerror(errno));
            result = MKA_NOT_OK;
        }
    }

    return result;
}

t_MKA_result MKA_l2_getLocalAddr(t_MKA_bus bus, uint8_t *addr)
{
    t_mka_l2_descriptor const*const l2 = &mka_l2[bus];
    memcpy(addr, l2->hw_addr, sizeof(l2->hw_addr));
    return l2->enabled ? MKA_OK : MKA_NOT_OK;
}

/** @} */
