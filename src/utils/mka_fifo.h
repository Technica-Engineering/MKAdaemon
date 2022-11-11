/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: mka_fifo.h
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
 * @file        mka_fifo.h
 * @version     1.0.0
 * @author      Andreu Montiel
 * @brief       MKA simple type-agnostic FIFO implementation
 *
 * @{
 */

#ifndef MKA_FIFO_H_
#define MKA_FIFO_H_

/*******************        Includes        *************************/
#include "mka_private.h"

//lint -save
//lint -e9026 [MISRA 2012 Directive 4.9, advisory] Function-like macros for readability

#ifdef __cplusplus
extern "C" {
#endif

/*******************        Defines           ***********************/
#define FIFO_MOD_ADD(a, b, mod) \
    ( (((a)+(b)) >= (mod)) ? ((a)+(b)-(mod)) : ((a)+(b)) )
#define FIFO_MIN(a, b)          \
    (((a) < (b)) ? (a) : (b))

/*******************        Types             ***********************/
typedef struct {
    uint16_t                used;       // Number of elements occupied
    uint16_t                first;      // Points to the head of the fifo
    uint16_t                last;       // Points to the tail of the fifo
    uint16_t                size;       // Max # of elements at the same time
    uint8_t*                buffer;
} t_fifo;

/*******************        Variables         ***********************/

/*******************        Func. prototypes  ***********************/

/*******************        Func. definition  ***********************/
static inline uint16_t fifo_available(t_fifo const* fifo) { return (fifo->size - fifo->used); }
static inline bool fifo_empty(t_fifo const* fifo) { return (0U == fifo->used); }
static inline bool fifo_full(t_fifo const* fifo) { return (fifo->used == fifo->size); }
static inline uint16_t fifo_occupied(t_fifo const* fifo) { return fifo->used; }
static inline void const* fifo_front(t_fifo const* fifo)
{
    //lint -e{9087} [MISRA 2012 Rule 11.3, required] cast is necessary due to type-agnostic nature of this fifo
    return (void const*)&fifo->buffer[fifo->first];
}
static inline void* fifo_back(t_fifo const* fifo)
{
    //lint -e{9087} [MISRA 2012 Rule 11.3, required] cast is necessary due to type-agnostic nature of this fifo
    return (void*)&fifo->buffer[fifo->last];
}
static inline void const* fifo_peek_last_inserted(t_fifo const* fifo, uint16_t size)
{
    // TODO: Should we implement some more API's and call this "deque"?
    uint16_t last_inserted = (size > fifo->last) ? (fifo->size - size) : (fifo->last - size);
    //lint -e{9087} [MISRA 2012 Rule 11.3, required] cast is necessary due to type-agnostic nature of this fifo
    return ((0U == (fifo->last % size)) && (fifo->used >= size)) ?
            (void const*)&fifo->buffer[last_inserted] : NULL;
}
static inline void fifo_reset(t_fifo* fifo)
{
    fifo->used = 0U;
    fifo->first = 0U;
    fifo->last = 0U;
}
static inline void fifo_init(t_fifo* fifo, uint16_t size, void* buffer)
{
    fifo->size = size;
    //lint -e{9079} [MISRA 2012 Rule 11.5, advisory] Unavoidable cast
    fifo->buffer = (uint8_t*)buffer;
    fifo_reset(fifo);
}
static inline bool fifo_inc_front(t_fifo* fifo, uint16_t how_much)
{
    bool inc_possible = (how_much <= fifo->used);
    if (inc_possible) {
        fifo->used -= how_much;
        fifo->first = FIFO_MOD_ADD(fifo->first, how_much, fifo->size);
    }
    return inc_possible;
}

static inline bool fifo_inc_back(t_fifo* fifo, uint16_t how_much)
{
    bool inc_possible = (how_much <= fifo_available(fifo));
    if (inc_possible) {
        fifo->used += how_much;
        fifo->last = FIFO_MOD_ADD(fifo->last, how_much, fifo->size);
    }
    return inc_possible;
}
static inline bool fifo_copy_to_tail(t_fifo const* fifo, void const*data, uint16_t how_much)
{
    bool is_space_free = (how_much <= fifo_available(fifo));
    //lint -e{9079} [MISRA 2012 Rule 11.5, advisory] Unavoidable cast
    uint8_t const*const data_u8 = (uint8_t const*)data;
    if (is_space_free) {
        uint16_t copy = FIFO_MIN(how_much, fifo->size-fifo->last);
        memcpy(&fifo->buffer[fifo->last], &data_u8[0U], copy);
        if (copy < how_much) {
            uint16_t remaining = how_much - copy;
            memcpy(&fifo->buffer[0], &data_u8[copy], remaining);
        }
    }
    return is_space_free;
}
static inline bool fifo_copy_from_head(t_fifo const* fifo, void *data, uint16_t how_much)
{
    bool is_space_occupied = (how_much <= fifo->used);
    //lint -e{9079} [MISRA 2012 Rule 11.5, advisory] Unavoidable cast
    uint8_t*const data_u8 = (uint8_t*)data;
    if (is_space_occupied) {
        uint16_t copy = FIFO_MIN(how_much, fifo->size-fifo->first);
        memcpy(&data_u8[0U], &fifo->buffer[fifo->first], copy);
        if (copy < how_much) {
            uint16_t remaining = how_much - copy;
            memcpy(&data_u8[copy], &fifo->buffer[0], remaining);
        }
    }
    return is_space_occupied;
}
static inline bool fifo_push(t_fifo* fifo, void const*data, uint16_t how_much)
{
    bool success = fifo_copy_to_tail(fifo, data, how_much);
    if (success) {
        (void)fifo_inc_back(fifo, how_much);
    }
    return success;
}
static inline bool fifo_pop(t_fifo* fifo, void *data, uint16_t how_much)
{
    bool success = fifo_copy_from_head(fifo, data, how_much);
    if (success) {
        (void)fifo_inc_front(fifo, how_much);
    }
    return success;
}


#ifdef __cplusplus
}
#endif

#endif /* MKA_FIFO_H_ */

//lint -restore

/** @} */


