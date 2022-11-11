/*******************************************************************************
*
* MKA daemon.
* SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
* SPDX-License-Identifier: GPL-2.0-or-later
* file: ut_helpers.h
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

#ifndef UT_HELPERS_H_
#define UT_HELPERS_H_
#include <stdio.h>
#include <string.h> // memmem
#include <unistd.h>
#include <yaml.h>

/* This will be used as a base class for the matchers below */
template <typename PTR_TYPE, size_t SKIP_AMOUNT=0>
class MemoryWithMatcher {
  protected:
    const char*         description;    /* Explains what the matcher is about */
    const PTR_TYPE*     expected_data;  /* Stores what the expected data is */
    const size_t        expected_size;  /* Stores the size of the expected data */

  public:
    /* Constructor initialising variables */
    MemoryWithMatcher(const PTR_TYPE *data, size_t size) : 
            description("pointer to buffer with expected data content"),
            expected_data(data),
            expected_size(size) {}

    /* Routine called by google mock. This executes the actual test of the matcher */
    bool MatchAndExplain(const PTR_TYPE *param, ::testing::MatchResultListener* listener) const {
        /* Prevent access to null -> segmentation fault */
        if (NULL == static_cast<const void*>(param)) {
            *listener << "cannot compare!";
            return false;
        }
        /* Compare data byte by byte, stop at the first difference and yield a message */
        for(size_t i=0; i<expected_size; i++) {
            if (expected_data[i] != param[SKIP_AMOUNT+i]) {
                *listener << "comparison fails at byte " << i << " expected [" << (int)expected_data[i] << "] found [" << (int)param[SKIP_AMOUNT+i] << "]";
                return false;
            }
        }
        /* Matcher test ok, return success */
        return true;
    }

    /* Google mock requests of description */
    void DescribeTo(::std::ostream* os) const { *os << description; }
    void DescribeNegationTo(::std::ostream* os) const { *os << "negative match to " << description; }
};

/* Make a matcher "MemoryWith" that lets user provide data pointer and size via argument.
 *
 * Usage (v1):
 *   EXPECT_CALL(mock_obj, library_memcpy(_, MemoryWith<const char>("hello", 5), 5));
 *
 * Usage (v2):
 *   EXPECT_THAT(some_variable, MemoryWith<const char>("hello, 5));
 *
 **/
template <typename PTR_TYPE>
inline ::testing::PolymorphicMatcher< MemoryWithMatcher<PTR_TYPE> > 
MemoryWith(PTR_TYPE *data, size_t size) {
    return ::testing::MakePolymorphicMatcher(MemoryWithMatcher<PTR_TYPE>(data, size));
}

/* Make a matcher "MemoryWithSkipping" that lets user provide data pointer and size via argument.
 *
 * Usage (v1):
 *   EXPECT_CALL(mock_obj, library_memcpy(_, MemoryWithSkipping<const char>("hello", 5), 5));
 *
 * Usage (v2):
 *   EXPECT_THAT(some_variable, MemoryWithSkipping<const char>("hello, 5));
 *
 **/
template <typename PTR_TYPE, int SKIP_AMOUNT>
inline ::testing::PolymorphicMatcher< MemoryWithMatcher<PTR_TYPE, SKIP_AMOUNT> > 
MemoryWithSkipping(PTR_TYPE *data, size_t size) {
    return ::testing::MakePolymorphicMatcher(MemoryWithMatcher<PTR_TYPE, SKIP_AMOUNT>(data, size));
}

/* Make a matcher "MemoryWith" that lets user provide size via template, and data via immediate array argument
 *
 * Usage (v1):
 *   EXPECT_CALL(mock_obj, library_memcpy(_, MemoryWith<6, const char>({'q', 'q', 'a', 'a', '\r', '\n'}), 6));
 *
 * Usage (v2):
 *   auto matcher_expecting_qqaa = MemoryWith<6, const char>({'q', 'q', 'a', 'a', '\r', '\n'});
 *   EXPECT_THAT(some_variable, matcher_expecting_qqaa);
 */
template <size_t SIZE, typename PTR_TYPE>
inline ::testing::PolymorphicMatcher< MemoryWithMatcher<PTR_TYPE> > 
MemoryWith(::std::initializer_list<PTR_TYPE> immediate_array) {
    return ::testing::MakePolymorphicMatcher(
        MemoryWithMatcher<PTR_TYPE>(
            immediate_array.begin(),
            SIZE
        )
    );
}

/* Make a matcher "MemoryWith" that lets user provide an immediate array via argument, implicit size
 *
 * Usage (v1):
 *   EXPECT_CALL(mock_obj, library_memcpy(_, MemoryWith<const char>({'a', 'a', 'a'})));
 *
 * Usage (v2):
 *   EXPECT_THAT(some_variable, MemoryWith<const char>({'a', 'a', 'a'}));
 *
 **/
template <typename PTR_TYPE>
inline ::testing::PolymorphicMatcher< MemoryWithMatcher<PTR_TYPE> > 
MemoryWith(::std::initializer_list<PTR_TYPE> immediate_array) {
    return ::testing::MakePolymorphicMatcher(
        MemoryWithMatcher<PTR_TYPE>(
            immediate_array.begin(),
            immediate_array.size()
        )
    );
}

template <typename PTR_TYPE>
inline ::testing::PolymorphicMatcher< MemoryWithMatcher<PTR_TYPE> >
ContainsRotatedMemory(int offset, const ::std::initializer_list<PTR_TYPE> &immediate_array) {
    const PTR_TYPE *immediate = immediate_array.begin();
    const int size = immediate_array.size();
    static PTR_TYPE rotData[ 16 ];

    for(int i=0; i<size; i++)
        rotData[(i+offset+size)%size] = immediate[i];

    return ::testing::MakePolymorphicMatcher(
        MemoryWithMatcher<PTR_TYPE>( rotData, size )
    );
}

#pragma GCC diagnostic ignored "-Wreturn-type"
/* Usage:
 * .WillRepeatedly( testing::DoAll(
 *         MemcpyToArg<0>(buffer, bufferSize),
 *         testing::Return( strlen( rcvBuffer ) ) ) );
 */
ACTION_TEMPLATE(MemcpyToArg, HAS_1_TEMPLATE_PARAMS(unsigned, uIndex), AND_2_VALUE_PARAMS(pData, uiDataSize))
{
    memcpy(std::get<uIndex>(args), pData, uiDataSize);
}
/* Usage:
 * .WillRepeatedly( testing::DoAll(
 *         MemcpyFromArg<0>(buffer, bufferSize),
 *         testing::Return( strlen( rcvBuffer ) ) ) );
 */
ACTION_TEMPLATE(MemcpyFromArg, HAS_1_TEMPLATE_PARAMS(unsigned, uIndex), AND_2_VALUE_PARAMS(pData, uiDataSize))
{
    memcpy(pData, std::get<uIndex>(args), uiDataSize);
}
/* Usage:
 * .WillRepeatedly( testing::DoAll(
 *         MemcpyFromArgToArgWithSize<0,1,2>(),
 *         testing::Return( strlen( rcvBuffer ) ) ) );
 */
ACTION_TEMPLATE(MemcpyFromArgToArgWithSize, HAS_3_TEMPLATE_PARAMS(unsigned, uDst, unsigned, uSrc, unsigned, uSize), AND_0_VALUE_PARAMS())
{
    memcpy(
        std::get<uDst>(args),   /* first template argument, dest */
        std::get<uSrc>(args),   /* second template argument, src */
        std::get<uSize>(args)   /* third template argument, size */
    );
}
#pragma GCC diagnostic pop

class LoggingMessageMatcher : public MemoryWithMatcher<char const> {
  public:
    LoggingMessageMatcher(const char *data) :
        MemoryWithMatcher(data, strlen(data)) {}
    /* Routine called by google mock. This executes the actual test of the matcher */
    bool MatchAndExplain(const char *param, ::testing::MatchResultListener* listener) const {
        /* Prevent access to null -> segmentation fault */
        if (NULL == static_cast<const void*>(param)) {
            *listener << "cannot compare!";
            return false;
        }
        /* Compare data byte by byte, stop at the first difference and yield a message */
        for(size_t i=0; i<expected_size; i++) {
            if ((i >= 6) && (i < 14)) {
                // Accept differences, this is the line number!
                continue;
            }
            if (expected_data[i] != param[i]) {
                *listener << "comparison fails at byte " << i << " expected [" << (char)expected_data[i] << "] found [" << (char)param[i] << "]";
                return false;
            }
        }
        /* Matcher test ok, return success */
        return true;
    }
};

inline ::testing::PolymorphicMatcher< LoggingMessageMatcher > 
LoggingMessage(char const *data) {
    return ::testing::MakePolymorphicMatcher(LoggingMessageMatcher(data));
}

struct LoggingMessageContainsMatcher {
    const char*         expected_data;  /* Stores what the expected data is */

    LoggingMessageContainsMatcher(const char *data) :
            expected_data(data)
         {}

    /* Routine called by google mock. This executes the actual test of the matcher */
    bool MatchAndExplain(const char *param, ::testing::MatchResultListener* listener) const {
        /* Prevent access to null -> segmentation fault */
        if (NULL == static_cast<const void*>(param)) {
            *listener << "cannot compare!";
            return false;
        }
        if (NULL == strstr(param, expected_data)) {
            *listener << "pattern [" << expected_data << "] not found in log message [" << param << "]";
            return false;
        }
        /* Matcher test ok, return success */
        return true;
    }

    /* Google mock requests of description */
    void DescribeTo(::std::ostream* os) const { *os << "string containing [" << expected_data << "]"; }
    void DescribeNegationTo(::std::ostream* os) const { *os << "negative match to " << "string containing [" << expected_data << "]"; }
};

inline ::testing::PolymorphicMatcher< LoggingMessageContainsMatcher > 
LoggingMessageContains(char const *data) {
    return ::testing::MakePolymorphicMatcher(LoggingMessageContainsMatcher(data));
}

/* This will be used as a base class for the matchers below */
template <typename PTR_TYPE>
class ObjectPointerMatcher {
  protected:
    const char*         description;    /* Explains what the matcher is about */
    const PTR_TYPE*     expected_data;  /* Stores what the expected data is */
    const size_t        expected_size;  /* Stores the size of the expected data */

  public:
    /* Constructor initialising variables */
    ObjectPointerMatcher(const PTR_TYPE *data, size_t size=1) : 
            description("pointer to expected object content"),
            expected_data(data),
            //expected_data((PTR_TYPE*)malloc(sizeof(PTR_TYPE) * size)),
            expected_size(size)
    {
    }
    ~ObjectPointerMatcher(void)
    {
    }

    static bool doCompare(const PTR_TYPE *a, const PTR_TYPE* b, size_t num, ::testing::MatchResultListener* listener) {
        /* Prevent access to null -> segmentation fault */
        if (NULL == static_cast<const void*>(a)) {
            *listener << "cannot compare!";
            return false;
        }
        /* Compare data byte by byte, stop at the first difference and yield a message */
        for(size_t i=0; i<num; i++) {
            if (0 != memcmp(&b[i], &a[i], sizeof(PTR_TYPE))) {
                *listener << "comparison fails at object #" << i;
                return false;
            }
        }
        /* Matcher test ok, return success */
        return true;
    }

    /* Routine called by google mock. This executes the actual test of the matcher */
    bool MatchAndExplain(const PTR_TYPE *param, ::testing::MatchResultListener* listener) const {
        return doCompare(param, expected_data, expected_size, listener);
    }

    // Syntactic sugar, please!
    bool MatchAndExplain(const PTR_TYPE &param, ::testing::MatchResultListener* listener) const {
        return doCompare(&param, expected_data, expected_size, listener);
    }

    /* Google mock requests of description */
    void DescribeTo(::std::ostream* os) const { *os << description; }
    void DescribeNegationTo(::std::ostream* os) const { *os << "negative match to " << description; }
};

/* Make a matcher "PointedObjectMatch" that lets user provide data pointer and size via argument.
 * REMARK: Supports objects with lack of equality comparison binary operator "=="!
 *
 * Usage (v1 although char spuports comparison):
 *   EXPECT_CALL(mock_obj, library_memcpy(_, PointedObjectMatch<const char>("hello", 5), 5));
 *
 * Usage (v2):
 *   EXPECT_THAT(some_variable, PointedObjectMatch<const char>("hello", 5));
 *
 **/
template <typename PTR_TYPE>
inline ::testing::PolymorphicMatcher< ObjectPointerMatcher<PTR_TYPE> > 
ObjectMatch(PTR_TYPE *data, size_t size = 1) {
    return ::testing::MakePolymorphicMatcher(ObjectPointerMatcher<PTR_TYPE>(data, size));
}

/* Make a matcher "ObjectMatch" that lets user provide single object.
 * REMARK: Supports objects with lack of equality comparison binary operator "=="!
 *
 **/
template <typename PTR_TYPE>
inline ::testing::PolymorphicMatcher< ObjectPointerMatcher<PTR_TYPE> > 
ObjectMatch(PTR_TYPE &obj) {
    return ::testing::MakePolymorphicMatcher(ObjectPointerMatcher<PTR_TYPE>(&obj, 1));
}

static inline void show_hex(char*what, uint8_t *data, uint32_t len)
{
	printf("Dumping [%s]:\n", what);
	for (int i=0;i<len;i++){
        printf("%02X ", data[i]);
        if ((i%8) == 7) printf(" ");
        if ((i%16) == 15) printf("\n");
	}
	printf("\n");
}
#define INDENT "  "
#define STRVAL(x) ((x) ? (char*)(x) : "")

static char const* ev2str[] = {
    "YAML_NO_EVENT",
    "YAML_STREAM_START_EVENT",
    "YAML_STREAM_END_EVENT",
    "YAML_DOCUMENT_START_EVENT",
    "YAML_DOCUMENT_END_EVENT",
    "YAML_ALIAS_EVENT",
    "YAML_SCALAR_EVENT",
    "YAML_SEQUENCE_START_EVENT",
    "YAML_SEQUENCE_END_EVENT",
    "YAML_MAPPING_START_EVENT",
    "YAML_MAPPING_END_EVEN",
};

static inline void indent(int level)
{
    int i;
    for (i = 0; i < level; i++) {
        printf("%s", INDENT);
    }
}

static inline void print_event(yaml_event_t *event)
{
    static int level = 0;

    switch (event->type) {
    case YAML_NO_EVENT:
        indent(level);
        printf("no-event (%d)\n", event->type);
        break;
    case YAML_STREAM_START_EVENT:
        indent(level++);
        printf("stream-start-event (%d)\n", event->type);
        break;
    case YAML_STREAM_END_EVENT:
        indent(--level);
        printf("stream-end-event (%d)\n", event->type);
        break;
    case YAML_DOCUMENT_START_EVENT:
        indent(level++);
        printf("document-start-event (%d)\n", event->type);
        break;
    case YAML_DOCUMENT_END_EVENT:
        indent(--level);
        printf("document-end-event (%d)\n", event->type);
        break;
    case YAML_ALIAS_EVENT:
        indent(level);
        printf("alias-event (%d)\n", event->type);
        break;
    case YAML_SCALAR_EVENT:
        indent(level);
        printf("scalar-event (%d) = {value=\"%s\", length=%d}\n",
               event->type,
               STRVAL(event->data.scalar.value),
               (int)event->data.scalar.length);
        break;
    case YAML_SEQUENCE_START_EVENT:
        indent(level++);
        printf("sequence-start-event (%d)\n", event->type);
        break;
    case YAML_SEQUENCE_END_EVENT:
        indent(--level);
        printf("sequence-end-event (%d)\n", event->type);
        break;
    case YAML_MAPPING_START_EVENT:
        indent(level++);
        printf("mapping-start-event (%d)\n", event->type);
        break;
    case YAML_MAPPING_END_EVENT:
        indent(--level);
        printf("mapping-end-event (%d)\n", event->type);
        break;
    }
    if (level < 0) {
        fprintf(stderr, "indentation underflow!\n");
        level = 0;
    }
}

struct TempFile {
    char folder[64];
    char name[64];
    TempFile(void) : folder("/tmp/mka_test_XXXXXX") {
        (void)snprintf(name, sizeof(name), "%s/test_settings.conf", mkdtemp(folder));
    }
    ~TempFile(void) {
        (void)unlink(name);
        (void)rmdir(folder);
    }
    operator char const*(void) const { return name; }
};


using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::Invoke;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::Gt;
using ::testing::Ge;
using ::testing::TypedEq;
using ::testing::NotNull;
using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::Pointee;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::SaveArg;
using ::testing::SaveArgPointee;
using ::testing::_;
using ::testing::Sequence;



#endif
