/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: test-fifo.cpp
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

/* Description: Unit test template.
 * Author: Your name here
 *
 * Execute the following command to run this test alone, without coverage:
 * $ python waf test --targets=test_name --coverage=no
 *
 * Execute the following command to run ALL tests:
 * $ python waf test
 *
 */
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "ut_helpers.h"
#include "mka_private.h"
#include "mka_fifo.h"


#define ASSERT_CONSISTENT()    \
        ASSERT_EQ(NULL, queueIsConsistent()) << queueIsConsistent()

class BasicQueueTest : public ::testing::Test {
  public:
    typedef uint16_t                                    t_size;
    typedef std::tuple<t_size, t_size, t_size, t_size>  t_state;
    typedef t_fifo                                      t_queue;

    char            buffer[1024];
    t_queue         queue;

    BasicQueueTest(void) {
        memset(buffer, 0, sizeof(buffer));
        fifo_init(&queue, 1024, buffer);
    }

    char* getStateString(void) const {
        static char state_string[1024];
        sprintf(state_string, "size: %i used: %i first: %i last: %i", 
            queue.size, queue.used, queue.first, queue.last);
        return state_string;
    }

    t_state getState(void) const {
        return std::make_tuple(queue.size, queue.used, queue.first, queue.last);
    }

    const char* queueIsConsistent(void) const {
        char* state = getStateString();
        t_size len = strlen(state);
        const t_size first = queue.first, last = queue.last, used = queue.used, size = queue.size;
        
        ( first  < size                              ) || strcat(state, ", first >= size");
        ( last   < size                              ) || strcat(state, ", last  >= size");
        ( size   > 0                                 ) || strcat(state, ", size  <= 0");
        ( used % size == ((size+last-first)%size)    ) || strcat(state, ", used != (last-first) mod size");
        ( (used != size) || (first == last)          ) || strcat(state, ", used == size and first != last");

        return (strlen(state) > len) ? state : NULL;
    }

    void setState(t_size size, t_size used, t_size first, t_size last) {
        ASSERT_CONSISTENT();

        /* Set state */
        queue.size  = size;
        queue.used          = used;
        queue.first         = first;
        queue.last          = last;
    }

    virtual void SetUp(void) = 0;
    virtual void TearDown(void) {
        ASSERT_CONSISTENT();
    }
};

class TestWith3ElemsParametersOccupancyAndFirst : public BasicQueueTest,
        public ::testing::WithParamInterface<std::tuple<uint16_t, uint16_t>> {
  public:
    const uint16_t size;
    const uint16_t used;
    const uint16_t first;
    uint16_t offset;
    uint16_t occupied;
    TestWith3ElemsParametersOccupancyAndFirst(void) : 
        size{3},
        used{std::get<0>(GetParam())},
        first{std::get<1>(GetParam())} {}
    
    virtual void SetUp(void) {
        setState(
            /* size     */  size,
            /* used     */  used,
            /* first    */  first,
            /* last     */  (first + used) % size
        );
    }
};

INSTANTIATE_TEST_SUITE_P(QueuePossibleStates, TestWith3ElemsParametersOccupancyAndFirst, ::testing::Values(
    std::make_tuple(0, 0), std::make_tuple(0, 1), std::make_tuple(0, 2),
    std::make_tuple(1, 0), std::make_tuple(1, 1), std::make_tuple(1, 2),
    std::make_tuple(2, 0), std::make_tuple(2, 1), std::make_tuple(2, 2)
));

TEST_P(TestWith3ElemsParametersOccupancyAndFirst, correct_state_after_reset) {
    fifo_reset(&queue);
    ASSERT_THAT(getState(), std::make_tuple(3, 0, 0, 0));
}

TEST_P(TestWith3ElemsParametersOccupancyAndFirst, correct_state_getters) {
    ASSERT_THAT(fifo_empty(&queue),     (used == 0) ? true : false);
    ASSERT_THAT(fifo_full(&queue),      (used == 3));
    ASSERT_THAT(fifo_occupied(&queue),  used);
    ASSERT_THAT(fifo_available(&queue), (3-used));

    ASSERT_EQ(&buffer[first],                   fifo_front(&queue));
    ASSERT_EQ(&buffer[(first+used)%size],       fifo_back(&queue));
}

#if 0
TEST_P(TestWith3ElemsParametersOccupancyAndFirst, correct_linear_getters)  {
    const uint16_t front_linear = (used > (3-first)) ? (3-first) : used;
    ASSERT_EQ(front_linear,     queue.front_linear());
    ASSERT_EQ(front_linear,     queue.front_linear(front_linear));
    ASSERT_EQ(front_linear,     queue.front_linear(3));
    ASSERT_EQ(0,                queue.front_linear(0));

    const uint16_t free = 3-used;
    const uint16_t last = (first + used) % size;
    const uint16_t back_linear = (free > (3-last)) ? (3-last) : free;
    ASSERT_EQ(back_linear,      queue.back_linear());
    ASSERT_EQ(back_linear,      queue.back_linear(back_linear));
    ASSERT_EQ(back_linear,      queue.back_linear(3));
    ASSERT_EQ(0,                queue.back_linear(0));
}
#endif

class TestWith3ElemsEmptyWithOffsetParameter : public BasicQueueTest,
        public ::testing::WithParamInterface<uint16_t> {
  public:
    const uint16_t offset;
    TestWith3ElemsEmptyWithOffsetParameter(void) : offset{GetParam()} {}
    virtual void SetUp(void) {
        setState(
            /* size     */  3u,
            /* used     */  0u,
            /* first    */  offset,
            /* last     */  offset
        );
    }
};


INSTANTIATE_TEST_SUITE_P(AllPossibleStatesVector, TestWith3ElemsEmptyWithOffsetParameter, ::testing::Values(0,1,2));

TEST_P(TestWith3ElemsEmptyWithOffsetParameter, push_size_one) {
    ASSERT_THAT(true,         fifo_push(&queue, "a", 1));
    ASSERT_THAT(getState(),   std::make_tuple(3, 1, offset, (offset+1)%3));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 0, 0}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'a'}));

    ASSERT_THAT(true,         fifo_push(&queue, "b", 1));
    ASSERT_THAT(getState(),   std::make_tuple(3, 2, offset, (offset+2)%3));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 'b', 0}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'b'}));

    ASSERT_THAT(true,         fifo_push(&queue, "c", 1));
    ASSERT_THAT(getState(),   std::make_tuple(3, 3, offset, offset));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 'b', 'c'}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'c'}));

    ASSERT_THAT(false,        fifo_push(&queue, "d", 1));
    ASSERT_THAT(getState(),   std::make_tuple(3, 3, offset, offset));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 'b', 'c'}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'c'}));
}

TEST_P(TestWith3ElemsEmptyWithOffsetParameter, push_size_two) {
    ASSERT_THAT(true,         fifo_push(&queue, "ab", 2));
    ASSERT_THAT(getState(),   std::make_tuple(3, 2, offset, (offset+2)%3));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 'b', 0}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'b'}));

    ASSERT_THAT(false,        fifo_push(&queue, "cd", 2));
    ASSERT_THAT(getState(),   std::make_tuple(3, 2, offset, (offset+2)%3));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 'b', 0}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'b'}));
}

TEST_P(TestWith3ElemsEmptyWithOffsetParameter, push_size_three) {
    ASSERT_THAT(true,         fifo_push(&queue, "abc", 3));
    ASSERT_THAT(getState(),   std::make_tuple(3, 3, offset, offset));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 'b', 'c'}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'c'}));

    ASSERT_THAT(false,        fifo_push(&queue, "def", 2));
    ASSERT_THAT(getState(),   std::make_tuple(3, 3, offset, offset));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {'a', 'b', 'c'}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), MemoryWith<char>({'c'}));
}

TEST_P(TestWith3ElemsEmptyWithOffsetParameter, push_size_four) {
    ASSERT_THAT(false,        fifo_push(&queue, "abcd", 4));
    ASSERT_THAT(getState(),   std::make_tuple(3, 0, offset, offset));
    ASSERT_THAT(buffer,       ContainsRotatedMemory<char>(offset, {0, 0, 0}));
    ASSERT_THAT((char const*)fifo_peek_last_inserted(&queue, 1), Eq(nullptr));
}

class TestWith3ElemsFullWithOffsetParameter : public BasicQueueTest,
        public ::testing::WithParamInterface<uint16_t> {
  public:
    char rbuffer[16];
    const uint16_t offset;
    TestWith3ElemsFullWithOffsetParameter(void) : offset{GetParam()} {
        memset(rbuffer, 0, sizeof(rbuffer));
    }
    virtual void SetUp(void) {
        setState(
            /* size     */  3u,
            /* used     */  0u,
            /* first    */  offset,
            /* last     */  offset
        );
        fifo_push(&queue, "abc", 3); /* Push works, we've tested it already */
    }
};

INSTANTIATE_TEST_SUITE_P(QueuePossibleOffsets, TestWith3ElemsFullWithOffsetParameter, ::testing::Values(0,1,2));

TEST_P(TestWith3ElemsFullWithOffsetParameter, pop_size_one) {
    ASSERT_THAT(true,           fifo_pop(&queue, rbuffer, 1));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'a', 0}));

    ASSERT_THAT(true,           fifo_pop(&queue, rbuffer, 1));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'b', 0}));

    ASSERT_THAT(true,           fifo_pop(&queue, rbuffer, 1));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'c', 0}));

    ASSERT_THAT(false,          fifo_pop(&queue, rbuffer, 1));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'c', 0}));
}

TEST_P(TestWith3ElemsFullWithOffsetParameter, pop_size_two) {
    ASSERT_THAT(true,           fifo_pop(&queue, rbuffer, 2));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'a', 'b', 0}));

    ASSERT_THAT(false,          fifo_pop(&queue, rbuffer, 2));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'a', 'b', 0}));
}

TEST_P(TestWith3ElemsFullWithOffsetParameter, pop_size_three) {
    ASSERT_THAT(true,           fifo_pop(&queue, rbuffer, 3));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'a', 'b', 'c', 0}));

    ASSERT_THAT(false,          fifo_pop(&queue, rbuffer, 3));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({'a', 'b', 'c', 0}));
}

TEST_P(TestWith3ElemsFullWithOffsetParameter, pop_size_four) {
    ASSERT_THAT(false,          fifo_pop(&queue, rbuffer, 4));
    ASSERT_THAT(rbuffer,        MemoryWith<char>({0}));
}

