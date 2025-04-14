// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 * -----------------------------------------------------------------------------
 * splinterdb_quick_test.c --
 *
 *     Quick test of the public API of SplinterDB
 *
 * NOTE: This test case file also serves as an example for how-to build
 *  CTests, and the syntax for different commands etc. Note the
 *  annotations to learn how to write new unit-tests using Ctests.
 *
 * Naming Conventions:
 *
 *  o The file containing unit-test cases for a module / functionality is
 *    expected to be named <something>_test.c
 *
 *  o Individual test cases [ see below ] in a file are prefaced with a
 *    term naming the test suite, for the module / functionality being tested.
 *    Usually it will just be <something>; .e.g., in splinterdb_test.c
 *    the suite-name is 'splinterdb_quick'.
 *
 *  o Each test case should be named test_<operation>
 * -----------------------------------------------------------------------------
 */
#include <stdlib.h> // Needed for system calls; e.g. free
#include <string.h>
#include <errno.h>

#include "splinterdb/splinterdb.h"
#include "splinterdb/data.h"
#include "splinterdb/public_platform.h"
#include "splinterdb/default_data_config.h"
#include "unit_tests.h"
#include "util.h"
#include "test_data.h"
#include "ctest.h" // This is required for all test-case files.
#include "btree.h" // for MAX_INLINE_MESSAGE_SIZE
#include "config.h"
#include "endian.h"
#include "trunk.h"

#define TEST_MAX_KEY_SIZE 13

/* -1 for message encoding overhead */
#define TEST_MAX_VALUE_SIZE 32

// Hard-coded format strings to generate key and values
// static const char key_fmt[] = "key-%04x";
// static const char val_fmt[] = "val-%04lx";
#define KEY_FMT_LENGTH         (8)
#define VAL_FMT_LENGTH         (8)
#define TEST_INSERT_KEY_LENGTH (KEY_FMT_LENGTH + 1)
#define TEST_INSERT_VAL_LENGTH (VAL_FMT_LENGTH + 1)

// Function Prototypes
static void
create_default_cfg(splinterdb_config *out_cfg, data_config *default_data_cfg);


// static int
// insert_some_keys(const int num_inserts, splinterdb *kvsb, uint64_t *keys);

// static int
// insert_keys(splinterdb *kvsb, const int minkey, int numkeys, const int incr);

// static int
// check_current_tuple(splinterdb_iterator *it, const uint64_t expected_i);

// static int
// test_two_step_iterator(splinterdb *kvsb,
//                        slice       start_key,
//                        uint64         num_keys,
//                        uint64         minkey,
//                        uint64         start_i,
//                        uint64         hop_i);

// static int
// custom_key_comparator(const data_config *cfg, slice key1, slice key2);

typedef struct {
   data_config super;
   uint64      num_comparisons;
} comparison_counting_data_config;

/*
 * Global data declaration macro:
 *
 * This is converted into a struct, with a generated name prefixed by the
 * suite name. This structure is then automatically passed to all tests in
 * the test suite. In this function, declare all structures and
 * variables that you need globally to setup Splinter. This macro essentially
 * resolves to a bunch of structure declarations, so no code fragments can
 * be added here.
 *
 * NOTE: All data structures will hang off of data->, where 'data' is a
 * global static variable manufactured by CTEST_SETUP() macro.
 */
CTEST_DATA(benchmark)
{
   splinterdb       *kvsb;
   splinterdb_config cfg;

   comparison_counting_data_config default_data_cfg;
};


// Optional setup function for suite, called before every test in suite
CTEST_SETUP(benchmark)
{
   default_data_config_init(TEST_MAX_KEY_SIZE, &data->default_data_cfg.super);
   create_default_cfg(&data->cfg, &data->default_data_cfg.super);
   data->cfg.use_shmem =
      config_parse_use_shmem(Ctest_argc, (char **)Ctest_argv);

   int rc = splinterdb_create(&data->cfg, &data->kvsb);
   ASSERT_EQUAL(0, rc);
   ASSERT_TRUE(TEST_MAX_VALUE_SIZE
               < MAX_INLINE_MESSAGE_SIZE(LAIO_DEFAULT_PAGE_SIZE));
}

// Optional teardown function for suite, called after every test in suite
CTEST_TEARDOWN(benchmark)
{
   if (data->kvsb) {
      splinterdb_close(&data->kvsb);
   }
}

/*
 * ***********************************************************************
 * All tests in each file are named with one term, which represents the
 * module / functionality you are testing. Here, it is: splinterdb_quick
 *
 * This is an individual test case, testing [usually] just one thing.
 * The 2nd term is the test-case name, e.g., 'test_basic_flow'.
 * ***********************************************************************
 */
/*
 *
 * Basic test case that exercises and validates the basic flow of the
 * Splinter APIs.  We exercise:
 *  - splinterdb_insert()
 *  - splinterdb_lookup() and
 *  - splinterdb_delete()
 *
 * Validate that they behave as expected, including some basic error
 * condition checking.
 */
CTEST2_SKIP(benchmark, test_basic_flow)
{
//    uint64_t  key_data = 1;
//    size_t    key_len  = sizeof(key_data);
//    slice  user_key = slice_create(key_len, &key_data);

//    splinterdb_lookup_result result;
//    splinterdb_lookup_result_init(data->kvsb, &result, 0, NULL);

//    int rc = splinterdb_lookup(data->kvsb, user_key, &result);
//    ASSERT_EQUAL(0, rc);

//    // Lookup of a non-existent key should return not-found.
//    ASSERT_FALSE(splinterdb_lookup_found(&result));

//    static char *to_insert_data = "some-value";
//    size_t       to_insert_len  = strlen(to_insert_data);
//    slice        to_insert      = slice_create(to_insert_len, to_insert_data);

//    // Basic insert of new key should succeed.
//    rc = splinterdb_insert(data->kvsb, user_key, to_insert);
//    ASSERT_EQUAL(0, rc);

//    // Lookup of inserted key should succeed.
//    rc = splinterdb_lookup(data->kvsb, user_key, &result);
//    ASSERT_EQUAL(0, rc);
//    ASSERT_TRUE(splinterdb_lookup_found(&result));

//    slice value;
//    rc = splinterdb_lookup_result_value(&result, &value);
//    ASSERT_EQUAL(0, rc);
//    ASSERT_EQUAL(to_insert_len, slice_length(value));
//    ASSERT_STREQN(to_insert_data, slice_data(value), slice_length(value));

//    // Delete key
//    rc = splinterdb_delete(data->kvsb, user_key);
//    ASSERT_EQUAL(0, rc);

//    // Deleted key should not be found
//    rc = splinterdb_lookup(data->kvsb, user_key, &result);
//    ASSERT_EQUAL(0, rc);
//    ASSERT_FALSE(splinterdb_lookup_found(&result));

//    splinterdb_lookup_result_deinit(&result);
}


CTEST2(benchmark, range_query_stress_test) {

    // fill tree with bunch of integer keys

    #define N_RANGES 10000

    uint64 curr_key = 0;

    uint64 range_starts[N_RANGES] = {0};

    uint64 range_counts[N_RANGES] = {0};

    uint64 range_width = (1UL << 20);

    for (uint64 i = 0; i < N_RANGES; i++){
        range_starts[i] = (i * 121532) % (1UL << 30);
    }


    for (uint64 i = 0; i < (1UL << 22); i++) {
        curr_key = ((curr_key + 7) * 41579) % (1UL << 30);
        
        for (uint64 ri = 0; ri < N_RANGES; ri++) {
            if (range_starts[ri] < curr_key && curr_key < (range_starts[ri] + range_width)) {
                range_counts[ri]++;
            }
        }

        uint64 be_key = htobe64(curr_key);

        slice next_key = slice_create(sizeof(uint64), &be_key);

        char msg[] = "arbitrary content, lots of bytes to push to disk";

        slice value = slice_create(sizeof(uint64), msg);

        splinterdb_insert(data->kvsb, next_key, value);
    }

    printf("inserts done\n");

    timestamp ts = platform_get_timestamp();

    uint64 nonempty_ranges = 0;
    for (uint64 i = 0; i < N_RANGES; i++){
        // if (range_counts[i]) nonempty_ranges++;

        // printf("[%lu - %lu]\n", range_starts[i], range_starts[i] + range_width);

        uint64 start = htobe64(range_starts[i]);

        slice start_key = slice_create(sizeof(uint64), &start);

        // uint64 end = htobe64(range_starts[i] + range_width);

        // slice end_key = slice_create(sizeof(uint64), &end);

        splinterdb_iterator *iter;
        // splinterdb_range_query(data->kvsb, &iter, start_key, end_key);
        splinterdb_iterator_init(data->kvsb, &iter, start_key);

        uint64 curr;
        do {
            splinterdb_iterator_next(iter);
            slice found_key, found_value;
            splinterdb_iterator_get_current(iter, &found_key, &found_value);

            if (!splinterdb_iterator_valid(iter)) {
                break;
            }

            curr = be64toh(*(uint64 *)slice_data(found_key));

        } while (curr <= range_starts[i] + range_width);

        splinterdb_iterator_deinit(iter);

        // if (range_counts[i]) {
        //     nonempty_ranges++;
        //     // printf("found key: %lu\n\n", be64toh(*(uint64 *)slice_data(found_key)));

        //     uint64 k = be64toh(*(uint64 *)slice_data(found_key));

        //     ASSERT_TRUE(range_starts[i] <= k);
        //     ASSERT_TRUE(k <= (range_starts[i] + range_width) );
        // }
    }

    printf("spent (%lu ms) on range queries\n", NSEC_TO_MSEC(platform_timestamp_elapsed(ts)));

    printf("nonempty ranges: %lu\n", nonempty_ranges);


}

static void
create_default_cfg(splinterdb_config *out_cfg, data_config *default_data_cfg)
{
   *out_cfg = (splinterdb_config){.filename   = TEST_DB_NAME,
                                  .cache_size = 1 * Giga,
                                  .disk_size  = 8 * Giga,
                                  .use_shmem  = FALSE,
                                  .data_cfg   = default_data_cfg};
}