// Copyright 2018-2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 *----------------------------------------------------------------------
 * routing_filter.c --
 *
 *     This file contains the implementation for a routing filter
 *----------------------------------------------------------------------
 */
#include "platform.h"
#include "routing_filter.h"
#include "PackedArray.h"
#include "mini_allocator.h"
#include "iterator.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <math.h>

#include "memento.h"
#include "memento_int.h"

#include "poison.h"

#define ROUTING_FPS_PER_PAGE 4096


/*
 *----------------------------------------------------------------------
 * routing_hdr: Disk-resident structure.
 *
 *       This header encodes the bucket counts for all buckets covered by a
 *       single index. Appears on pages of page type == PAGE_TYPE_FILTER.
 *----------------------------------------------------------------------
 */
typedef struct ONDISK routing_hdr {
   uint16 num_remainders;
   char   encoding[];
} routing_hdr;

/*
 *----------------------------------------------------------------------
 * RadixSort --
 *
 *      A fast integer sort based on https://stackoverflow.com/a/44792724
 *----------------------------------------------------------------------
 */

// A 4x256 matrix is used for RadixSort
#define MATRIX_ROWS sizeof(uint32)
#define MATRIX_COLS (UINT8_MAX + 1)

// XXX Change arguments to struct
static uint32 *
RadixSort(uint32 *pData,
          uint32  mBuf[static MATRIX_ROWS * MATRIX_COLS],
          uint32 *pTemp,
          uint32  count,
          uint32  fp_size,
          uint32  value_size)
{
   uint32 *mIndex[MATRIX_ROWS]; // index matrix
   uint32 *pDst, *pSrc, *pTmp;
   uint32  i, j, m, n;
   uint32  u;
   uint32  fpover = value_size % 8;
   if (fp_size == 0) {
      fp_size = 1;
   }
   uint32 rounds = (fp_size + fpover - 1) / 8 + 1;
   uint8  c;
   uint32 fpshift = value_size / 8;
   value_size     = value_size / 8 * 8;

   for (i = 0; i < MATRIX_ROWS; i++) {
      mIndex[i] = &mBuf[i * MATRIX_COLS];
      for (ptrdiff_t j = 0; j < MATRIX_COLS; j++) {
         platform_assert(mIndex[i][j] == 0);
      }
   }
   for (i = 0; i < count; i++) { // generate histograms
      u = pData[i] >> value_size;
      for (j = 0; j < rounds; j++) {
         c = ((uint8 *)&u)[j];
         mIndex[j][c]++;
         debug_assert(mIndex[j][c] <= count);
      }
   }

   for (j = 0; j < rounds; j++) { // convert to indices
      n = 0;
      for (i = 0; i < MATRIX_COLS; i++) {
         m            = mIndex[j][i];
         mIndex[j][i] = n;
         platform_assert(mIndex[j][i] <= count);
         n += m;
      }
   }

   pDst = pTemp; // radix sort
   pSrc = pData;
   for (j = 0; j < rounds; j++) {
      for (i = 0; i < count; i++) {
         u = pSrc[i];
         c = ((uint8 *)&u)[j + fpshift];
         platform_assert((mIndex[j][c] < count),
                         "OS-pid=%d, thread-ID=%lu, i=%u, j=%u, c=%d"
                         ", mIndex[j][c]=%d, count=%u\n",
                         platform_getpid(),
                         platform_get_tid(),
                         i,
                         j,
                         c,
                         mIndex[j][c],
                         count);
         pDst[mIndex[j][c]++] = u;
      }
      pTmp = pSrc;
      pSrc = pDst;
      pDst = pTmp;
   }

   return (pSrc);
}


/*
 *----------------------------------------------------------------------
 *
 * Utility functions
 *
 *----------------------------------------------------------------------
 */

debug_only static inline void
routing_set_bit(uint64 *data, uint64 bitnum)
{
   *(data + bitnum / 64) |= (1ULL << (bitnum % 64));
}

static inline void
routing_unset_bit(uint64 *data, uint64 bitnum)
{
   *(data + bitnum / 64) &= ~((1ULL << (bitnum % 64)));
}

static inline uint32
routing_get_bucket(uint32 fp, size_t remainder_and_value_size)
{
   return fp >> remainder_and_value_size;
}

static inline uint32
routing_get_index(uint32 fp, size_t index_remainder_and_value_size)
{
   return index_remainder_and_value_size == 32
             ? 0
             : fp >> index_remainder_and_value_size;
}

static inline void
routing_filter_get_remainder_and_value(routing_config *cfg,
                                       uint32         *data,
                                       uint32          pos,
                                       uint32         *remainder_and_value,
                                       size_t          remainder_value_size)
{
   *remainder_and_value = PackedArray_get(data, pos, remainder_value_size);
}

static inline routing_hdr *
routing_get_header(cache          *cc,
                   routing_config *cfg,
                   uint64          filter_addr,
                   uint64          index,
                   page_handle   **filter_page)
{
   uint64 page_size      = cache_config_page_size(cfg->cache_cfg);
   uint64 addrs_per_page = page_size / sizeof(uint64);
   debug_assert(index / addrs_per_page < 32);
   uint64       index_addr = filter_addr + page_size * (index / addrs_per_page);
   page_handle *index_page = cache_get(cc, index_addr, TRUE, PAGE_TYPE_FILTER);
   uint64 hdr_raw_addr = ((uint64 *)index_page->data)[index % addrs_per_page];
   platform_assert(hdr_raw_addr != 0);
   uint64 header_addr      = hdr_raw_addr - (hdr_raw_addr % page_size);
   *filter_page            = cache_get(cc, header_addr, TRUE, PAGE_TYPE_FILTER);
   uint64       header_off = hdr_raw_addr - header_addr;
   routing_hdr *hdr        = (routing_hdr *)((*filter_page)->data + header_off);
   cache_unget(cc, index_page);
   return hdr;
}

static inline void
routing_unget_header(cache *cc, page_handle *header_page)
{
   cache_unget(cc, header_page);
}

static inline uint64
routing_header_length(routing_config *cfg, routing_hdr *hdr)
{
   uint64 metamessage_size =
      (hdr->num_remainders + cfg->index_size - 1) / 8 + 4;
   return metamessage_size + sizeof(routing_hdr);
}

static inline void
routing_unlock_and_unget_page(cache *cc, page_handle *page)
{
   cache_unlock(cc, page);
   cache_unclaim(cc, page);
   cache_unget(cc, page);
}

/*
 *----------------------------------------------------------------------
 * routing_get_bucket_bounds
 *
 *      parses the encoding to return the start and end indices for the
 *      bucket_offset
 *----------------------------------------------------------------------
 */
static inline void
routing_get_bucket_bounds(char   *encoding,
                          uint64  len,
                          uint64  bucket_offset,
                          uint64 *start,
                          uint64 *end)
{
   uint32 word          = 0;
   uint32 encoding_word = 0;
   uint64 bucket        = 0;
   uint64 bucket_pop    = 0;
   uint64 bit_offset    = 0;

   if (bucket_offset == 0) {
      *start        = 0;
      word          = 0;
      encoding_word = *((uint32 *)encoding + word);
      while (encoding_word == 0) {
         word++;
         encoding_word = *((uint32 *)encoding + word);
      }

      // ffs returns the index + 1 ALEX: I think that's what we want though.
      bit_offset = __builtin_ffs(encoding_word) - 1;
      *end       = 32 * word + bit_offset;
   } else {
      bucket_pop = __builtin_popcount(*((uint32 *)encoding));
      while (4 * word < len && bucket + bucket_pop < bucket_offset) {
         bucket += bucket_pop;
         word++;
         bucket_pop = __builtin_popcount(*((uint32 *)encoding + word));
      }

      encoding_word = *((uint32 *)encoding + word);
      while (bucket < bucket_offset - 1) {
         encoding_word &= encoding_word - 1;
         bucket++;
      }
      bit_offset = __builtin_ffs(encoding_word) - 1;
      *start     = 32 * word + bit_offset - bucket_offset + 1;

      encoding_word &= encoding_word - 1;
      while (encoding_word == 0) {
         word++;
         encoding_word = *((uint32 *)encoding + word);
      }
      bit_offset = __builtin_ffs(encoding_word) - 1; // ffs returns index + 1
      *end       = 32 * word + bit_offset - bucket_offset;
   }
}

void
routing_get_bucket_counts(routing_config *cfg, routing_hdr *hdr, uint32 *count)
{
   uint64  start = 0;
   uint64  end;
   uint64  i;
   uint64 *word_cursor = (uint64 *)hdr->encoding;
   uint64  word        = *(word_cursor++);

   memset(count, 0, cfg->index_size * sizeof(uint32));

   for (i = 0; i < cfg->index_size; i++) {
      while (word == 0) {
         count[i] += 64 - start;
         start = 0;
         word  = *(word_cursor++);
      }
      end = __builtin_ffsll(word) - 1;
      debug_assert(end - start < 1000);
      word &= word - 1;
      count[i] += end - start;
      start = end + 1;
   }
}

/*
 *----------------------------------------------------------------------
 *
 * unroll
 *
 *        Converts a routing filter into a fingerprint array
 *
 *----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 *
 * MAIN API
 *
 *----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 * routing_filter_add
 *
 *      Adds the fingerprints in fp_arr with value value to the
 *      routing filter at old_filter_addr and returns the result in
 *      filter_addr.
 *
 *      meta_head should be passed to routing_filter_zap
 *----------------------------------------------------------------------
 */
platform_status
routing_filter_add(cache                  *cc,
                   routing_config         *cfg,
                   routing_filter *old_filter,
                   routing_filter *filter,
                   uint32                 *new_fp_arr,
                   uint64                  num_new_fp,
                   uint16                  value)
{
   ZERO_CONTENTS(filter);   
   platform_assert(value < 24);
   
   if (old_filter->addr != 0) {
      mini_unkeyed_prefetch(cc, PAGE_TYPE_FILTER, old_filter->meta_head);
      }

   // compute parameters
   filter->num_fingerprints = num_new_fp + old_filter->num_fingerprints;

   // for convenience
   uint64 page_size        = cache_config_page_size(cfg->cache_cfg);
   uint64 extent_size      = cache_config_extent_size(cfg->cache_cfg);
   uint64 pages_per_extent = cache_config_pages_per_extent(cfg->cache_cfg);
   uint64 index_size       = cfg->index_size;

   allocator      *al = cache_get_allocator(cc);
   uint64          meta_head;
   platform_status rc = allocator_alloc(al, &meta_head, PAGE_TYPE_FILTER);
   platform_assert_status_ok(rc);
   filter->meta_head = meta_head;
   mini_allocator mini;
   mini_init(&mini, cc, NULL, filter->meta_head, 0, 1, PAGE_TYPE_FILTER, FALSE);
   platform_assert(filter->meta_head != old_filter->meta_head);

   page_handle *pages[N_PAGES * 24];

   uint64_t i = 0;
   if (old_filter->addr != 0) {
      page_handle *old_index_page = cache_get(cc, old_filter->addr, TRUE, PAGE_TYPE_FILTER);
      qf_index_page *old_index = (qf_index_page *) (old_index_page->data);

      uint64_t next_index_addr = mini_alloc(&mini, 0, NULL_KEY, NULL);
      pages[0] = cache_alloc(cc, next_index_addr, PAGE_TYPE_FILTER);
      memset(pages[0]->data, 0, 4096);
      i++;

      for (; i < N_PAGES * 24; i++) {
         if (i > 0 && i % N_PAGES == 0 && old_index->next_filter != 0) {
            uint64_t next_filter_addr = old_index->next_filter;
            cache_unget(cc, old_index_page);
            old_index_page = cache_get(cc, next_filter_addr, TRUE, PAGE_TYPE_FILTER);
            old_index = (qf_index_page *) (old_index_page->data);

            next_index_addr = mini_alloc(&mini, 0, NULL_KEY, NULL);
            pages[i] = cache_alloc(cc, next_index_addr, PAGE_TYPE_FILTER);
            memset(pages[i]->data, 0, 4096);
            continue;
         } else if (i > 0 && i % N_PAGES == 0 && old_index->next_filter == 0) {
            break;
         }

         next_index_addr = mini_alloc(&mini, 0, NULL_KEY, NULL);
         pages[i] = cache_alloc(cc, next_index_addr, PAGE_TYPE_FILTER);
         cache_assert_ungot(cc, old_index->page_addrs[(i - 1) % N_PAGES]);

         page_handle *old_page = cache_get(cc, old_index->page_addrs[(i - 1) % N_PAGES], TRUE, PAGE_TYPE_FILTER);

         memcpy(pages[i]->data, old_page->data, 4096);

         cache_unget(cc, old_page);
      }
      cache_unget(cc, old_index_page);
   }
   
   for (; i < N_PAGES * 24; i++) {
      uint64_t next_index_addr = mini_alloc(&mini, 0, NULL_KEY, NULL);
      pages[i] = cache_alloc(cc, next_index_addr, PAGE_TYPE_FILTER);
      memset(pages[i]->data, 0, 4096);
   }
   filter->addr = pages[0]->disk_addr;

   QF qf;
   qf_init_pages(&qf, 1024 * (N_PAGES - 3), 38, MEMENTO_BITS, QF_HASH_NONE, 0xBEEF, pages + (value * N_PAGES), N_PAGES, 2);
   if (value != 0) {
      ((qf_index_page *) pages[(value - 1) * N_PAGES]->data)->next_filter = pages[value * N_PAGES]->disk_addr;
   }
   
   for (i = 0; i < num_new_fp; i++) {
      uint32_t memento = new_fp_arr[i] & ((1ULL << MEMENTO_BITS) - 1);
      uint32_t fp = new_fp_arr[i] >> MEMENTO_BITS;
      qf_insert_single(&qf, fp, memento, QF_WAIT_FOR_LOCK | QF_KEY_IS_HASH);
   }

   for (i = 0; i < N_PAGES * 24; i++) {
      routing_unlock_and_unget_page(cc, pages[i]);
   }

   mini_release(&mini, NULL_KEY);   

   return STATUS_OK;
}

void
routing_filter_prefetch(cache          *cc,
                        routing_config *cfg,
                        routing_filter *filter,
                        uint64          num_indices)
{
   uint64 last_extent_addr = 0;
   uint64 page_size        = cache_config_page_size(cfg->cache_cfg);
   uint64 addrs_per_page   = page_size / sizeof(uint64);
   uint64 num_index_pages  = (num_indices - 1) / addrs_per_page + 1;
   uint64 index_no         = 0;

   for (uint64 index_page_no = 0; index_page_no < num_index_pages;
        index_page_no++)
   {
      uint64       index_addr = filter->addr + (page_size * index_page_no);
      page_handle *index_page =
         cache_get(cc, index_addr, TRUE, PAGE_TYPE_FILTER);
      platform_assert(index_no < num_indices);

      uint64 max_index_no;
      if (index_page_no == num_index_pages - 1) {
         max_index_no = num_indices % addrs_per_page;
         if (max_index_no == 0) {
            max_index_no = addrs_per_page;
         }
      } else {
         max_index_no = addrs_per_page;
      }
      for (index_no = 0; index_no < max_index_no; index_no++) {
         uint64 hdr_raw_addr =
            ((uint64 *)index_page->data)[index_no % addrs_per_page];
         uint64 extent_addr =
            hdr_raw_addr
            - (hdr_raw_addr % cache_config_extent_size(cfg->cache_cfg));
         if (extent_addr != last_extent_addr) {
            cache_prefetch(cc, extent_addr, PAGE_TYPE_FILTER);
            last_extent_addr = extent_addr;
         }
      }
      cache_unget(cc, index_page);
   }
}

uint32
routing_filter_estimate_unique_fp(cache           *cc,
                                  routing_config  *cfg,
                                  platform_heap_id hid,
                                  routing_filter  *filter,
                                  uint64           num_filters)
{
   if (filter->addr == 0) {
      return 0;
   }

   uint64_t total = 0;
   page_handle *filter_page;
   uint64_t next_addr = filter->addr;
   for (uint64_t n = 0; n < num_filters; n++) {
      filter_page = cache_get(cc, next_addr, TRUE, PAGE_TYPE_FILTER);
      qf_index_page *index = (qf_index_page *) filter_page->data;
      qfmetadata *meta = (qfmetadata *) (index+1);
      
      total += meta->nelts;

      if (index->next_filter == 0) {
         cache_unget(cc, filter_page);
         return total;
      }

      next_addr = index->next_filter;
      cache_unget(cc, filter_page);
   }

   return total;
}

/*
 *----------------------------------------------------------------------
 * routing_filter_lookup
 *
 *      Looks for key in the filter and returns whether it was found, it's
 *      value goes in found_values.
 *
 *      IMPORTANT: If there are multiple matching values, this function returns
 *      them in the reverse order.
 *----------------------------------------------------------------------
 */
platform_status
routing_filter_lookup(cache          *cc,
                      routing_config *cfg,
                      routing_filter *filter,
                      key             target,
                      uint64         *found_values)
{
   debug_assert(key_is_user_key(target));

   if (filter->addr == 0) {
      *found_values = 0;
      return STATUS_OK;
   }

   hash_fn   hash       = cfg->hash;
   uint64_t  seed       = cfg->seed;
   uint64_t  index_size = cfg->index_size;
   uint64_t  page_size  = cache_config_page_size(cfg->cache_cfg);

   uint32_t fp = hash(key_data(target), key_length(target), seed) << MEMENTO_BITS;
   fp >>= MEMENTO_BITS;
   uint32 memento = be64toh(*(uint64_t *)key_data(target)) & ((1UL << MEMENTO_BITS) - 1);

   uint64_t found_values_int = 0;
   page_handle *pages[N_PAGES * 24] = {0};

   pages[0] = cache_get(cc, filter->addr, TRUE, PAGE_TYPE_FILTER); 
   qf_index_page *index = (qf_index_page *)(pages[0]->data); 
   uint64_t n_filters = 1;

   for (uint64_t i = 1; i < N_PAGES * 24; i++) {
      if (i % N_PAGES == 0) {
         if (index->next_filter == 0) {
            break;
         }
         
         n_filters++;
         pages[i] = cache_get(cc, index->next_filter, TRUE, PAGE_TYPE_FILTER);
         index = (qf_index_page *)(pages[i]->data);
         continue;
      }
      uint64_t next_addr = index->page_addrs[(i - 1) % N_PAGES];
      pages[i] = cache_get(cc, next_addr, TRUE, PAGE_TYPE_FILTER);

   }


   for (uint16_t val = 0; val < n_filters; val++) {
      QF qf;
      qf_use_pages(&qf, pages + (N_PAGES * val));
      int found = qf_point_query(&qf, fp, memento, QF_WAIT_FOR_LOCK | QF_KEY_IS_HASH);
      if (found != 0) {
         found_values_int |= (1UL << val);
      }
   }

   for (uint64_t i = 0; i < N_PAGES * n_filters; i++) {
      cache_unget(cc, pages[i]);
   }

   *found_values = found_values_int;
   return STATUS_OK;
}


/*
 *----------------------------------------------------------------------
 * routing_filter_lookup
 *
 *      Looks for range in the filter and returns whether it was found, it's
 *      value goes in found_values.
 *
 *      IMPORTANT: If there are multiple matching values, this function returns
 *      them in the reverse order.
 *----------------------------------------------------------------------
 */
platform_status
routing_filter_lookup_range(cache          *cc,
                            routing_config *cfg,
                            routing_filter *filter,
                            key             min,
                            key             max,
                            uint64         *found_values)
{
   debug_assert(key_is_user_key(min));
   debug_assert(key_is_user_key(max));

   if (filter->addr == 0) {
      *found_values = 0;
      return STATUS_OK;
   }

   hash_fn   hash       = cfg->hash;
   uint64_t  seed       = cfg->seed;
   uint64_t  index_size = cfg->index_size;
   uint64_t  page_size  = cache_config_page_size(cfg->cache_cfg);

   uint32_t min_fp = hash(key_data(min), key_length(min), seed) << MEMENTO_BITS;
   uint32_t max_fp = hash(key_data(max), key_length(max), seed) << MEMENTO_BITS;
   
   min_fp >>= MEMENTO_BITS;
   max_fp >>= MEMENTO_BITS;

   uint32_t min_memento = be64toh(*(uint64_t *)key_data(min)) & ((1ULL << MEMENTO_BITS) - 1);
   uint32_t max_memento = be64toh(*(uint64_t *)key_data(max)) & ((1ULL << MEMENTO_BITS) - 1);
   uint64_t found_values_int = 0;
   page_handle *pages[N_PAGES * 24] = {0};

   pages[0] = cache_get(cc, filter->addr, TRUE, PAGE_TYPE_FILTER); 
   qf_index_page *index = (qf_index_page *)(pages[0]->data); 
   uint64_t n_filters = 1;

   for (uint64_t i = 1; i < N_PAGES * 24; i++) {
      if (i % N_PAGES == 0) {
         if (index->next_filter == 0) {
            break;
         }
         
         n_filters++;
         pages[i] = cache_get(cc, index->next_filter, TRUE, PAGE_TYPE_FILTER);
         index = (qf_index_page *)(pages[i]->data);
         continue;
      }
      uint64_t next_addr = index->page_addrs[(i - 1) % N_PAGES];
      pages[i] = cache_get(cc, next_addr, TRUE, PAGE_TYPE_FILTER);

   }


   for (uint16_t val = 0; val < n_filters; val++) {
      QF qf;
      qf_use_pages(&qf, pages + (N_PAGES * val));
      int found = qf_range_query(&qf, min_fp, min_memento, max_fp, max_memento, QF_WAIT_FOR_LOCK | QF_KEY_IS_HASH);
      if (found != 0) {
         found_values_int |= (1UL << val);
      }
   }

   for (uint64_t i = 0; i < N_PAGES * n_filters; i++) {
      cache_unget(cc, pages[i]);
   }

   *found_values = found_values_int;
   return STATUS_OK;
}

/*
 *-----------------------------------------------------------------------------
 * routing_async_set_state --
 *
 *      Set the state of the async filter lookup state machine.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *-----------------------------------------------------------------------------
 */
static inline void
routing_async_set_state(routing_async_ctxt *ctxt, routing_async_state new_state)
{
   ctxt->prev_state = ctxt->state;
   ctxt->state      = new_state;
}


/*
 *-----------------------------------------------------------------------------
 * routing_filter_async_callback --
 *
 *      Callback that's called when the async cache get loads a page into
 *      the cache. This function moves the async filter lookup state machine's
 *      state ahead, and calls the upper layer callback that'll re-enqueue
 *      the filter lookup for dispatch.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *-----------------------------------------------------------------------------
 */
static void
routing_filter_async_callback(cache_async_ctxt *cache_ctxt)
{
   routing_async_ctxt *ctxt = cache_ctxt->cbdata;

   platform_assert(SUCCESS(cache_ctxt->status));
   platform_assert(cache_ctxt->page);
   //   platform_default_log("%s:%d tid %2lu: ctxt %p is callback with page
   //   %p\n",
   //                __FILE__, __LINE__, platform_get_tid(), ctxt,
   //                cache_ctxt->page);
   ctxt->was_async = TRUE;
   // Move state machine ahead and requeue for dispatch
   if (ctxt->state == routing_async_state_get_index) {
      routing_async_set_state(ctxt, routing_async_state_got_index);
   } else {
      debug_assert(ctxt->state == routing_async_state_get_filter);
      routing_async_set_state(ctxt, routing_async_state_got_filter);
   }
   ctxt->cb(ctxt);
}


/*
 *-----------------------------------------------------------------------------
 * routing_filter_lookup_async --
 *
 *      Async filter lookup api. Returns if lookup found a key in *found_values.
 *      The ctxt should've been initialized using routing_filter_ctxt_init().
 *      The return value can be either of:
 *      async_locked: A page needed by lookup is locked. User should retry
 *                    request.
 *      async_no_reqs: A page needed by lookup is not in cache and the IO
 *                     subsystem is out of requests. User should throttle.
 *      async_io_started: Async IO was started to read a page needed by the
 *                        lookup into the cache. When the read is done, caller
 *                        will be notified using ctxt->cb, that won't run on
 *                        the thread context. It can be used to requeue the
 *                        async lookup request for dispatch in thread context.
 *                        When it's requeued, it must use the same function
 *                        params except found.
 *      success: Results are in *found_values
 *
 * Results:
 *      Async result.
 *
 * Side effects:
 *      None.
 *-----------------------------------------------------------------------------
 */
cache_async_result
routing_filter_lookup_async(cache              *cc,
                            routing_config     *cfg,
                            routing_filter     *filter,
                            key                 target,
                            uint64             *found_values,
                            routing_async_ctxt *ctxt)
{
   cache_async_result res  = 0;
   bool32             done = FALSE;

   debug_assert(key_is_user_key(target));

   uint64 page_size = cache_config_page_size(cfg->cache_cfg);
   do {
      switch (ctxt->state) {
         case routing_async_state_start:
         {
            // Calculate filter parameters for the key
            hash_fn hash = cfg->hash;
            uint64  seed = cfg->seed;

            uint32 fp = hash(key_data(target), key_length(target), seed);
            fp >>= 32 - cfg->fingerprint_size;
            size_t value_size = filter->value_size;
            uint32 log_num_buckets =
               31 - __builtin_clz(filter->num_fingerprints);
            if (log_num_buckets < cfg->log_index_size) {
               log_num_buckets = cfg->log_index_size;
            }
            ctxt->remainder_size = cfg->fingerprint_size - log_num_buckets;
            size_t remainder_and_value_size = ctxt->remainder_size + value_size;
            ctxt->bucket =
               routing_get_bucket(fp << value_size, remainder_and_value_size);
            size_t index_remainder_and_value_size =
               ctxt->remainder_size + value_size + cfg->log_index_size;
            uint32 remainder_mask = (1UL << ctxt->remainder_size) - 1;
            ctxt->index           = routing_get_index(fp << value_size,
                                            index_remainder_and_value_size);
            ctxt->remainder       = fp & remainder_mask;

            uint64 addrs_per_page = (page_size / sizeof(uint64));
            ctxt->page_addr =
               filter->addr + page_size * (ctxt->index / addrs_per_page);
            routing_async_set_state(ctxt, routing_async_state_get_index);
            // fallthrough;
         }
         case routing_async_state_get_index:
         case routing_async_state_get_filter:
         {
            // Get the index or filter page.
            cache_async_ctxt *cache_ctxt = ctxt->cache_ctxt;

            cache_ctxt_init(
               cc, routing_filter_async_callback, ctxt, cache_ctxt);
            res = cache_get_async(
               cc, ctxt->page_addr, PAGE_TYPE_FILTER, cache_ctxt);
            switch (res) {
               case async_locked:
               case async_no_reqs:
                  //            platform_default_log("%s:%d tid %2lu: ctxt %p is
                  //            retry\n",
                  //                         __FILE__, __LINE__,
                  //                         platform_get_tid(), ctxt);
                  /*
                   * Ctxt remains at same state. The invocation is done, but
                   * the request isn't; and caller will re-invoke me.
                   */
                  done = TRUE;
                  break;
               case async_io_started:
                  //            platform_default_log("%s:%d tid %2lu: ctxt %p is
                  //            io_started\n",
                  //                         __FILE__, __LINE__,
                  //                         platform_get_tid(), ctxt);
                  // Invocation is done; request isn't. Callback will move
                  // state.
                  done = TRUE;
                  break;
               case async_success:
                  ctxt->was_async = FALSE;
                  if (ctxt->state == routing_async_state_get_index) {
                     routing_async_set_state(ctxt,
                                             routing_async_state_got_index);
                  } else {
                     debug_assert(ctxt->state
                                  == routing_async_state_get_filter);
                     routing_async_set_state(ctxt,
                                             routing_async_state_got_filter);
                  }
                  break;
               default:
                  platform_assert(0);
            }
            break;
         }
         case routing_async_state_got_index:
         {
            // Got the index; find address of filter page
            cache_async_ctxt *cache_ctxt = ctxt->cache_ctxt;

            if (ctxt->was_async) {
               cache_async_done(cc, PAGE_TYPE_FILTER, cache_ctxt);
            }
            uint64 *index_arr      = ((uint64 *)cache_ctxt->page->data);
            uint64  addrs_per_page = (page_size / sizeof(uint64));
            ctxt->header_addr      = index_arr[ctxt->index % addrs_per_page];
            ctxt->page_addr =
               ctxt->header_addr - (ctxt->header_addr % page_size);
            cache_unget(cc, cache_ctxt->page);
            routing_async_set_state(ctxt, routing_async_state_get_filter);
            break;
         }
         case routing_async_state_got_filter:
         {
            // Got the filter; find bucket and search for remainder
            cache_async_ctxt *cache_ctxt = ctxt->cache_ctxt;

            if (ctxt->was_async) {
               cache_async_done(cc, PAGE_TYPE_FILTER, cache_ctxt);
            }
            routing_hdr *hdr =
               (routing_hdr *)(cache_ctxt->page->data
                               + (ctxt->header_addr % page_size));
            uint64 encoding_size =
               (hdr->num_remainders + cfg->index_size - 1) / 8 + 4;
            uint64 header_length = encoding_size + sizeof(routing_hdr);
            uint64 start, end;
            uint32 bucket_off = ctxt->bucket % cfg->index_size;
            routing_get_bucket_bounds(
               hdr->encoding, header_length, bucket_off, &start, &end);
            char *remainder_block_start = (char *)hdr + header_length;

            uint64 found_values_int = 0;
            for (uint32 i = 0; i < end - start; i++) {
               uint32 pos = end - i - 1;
               uint32 found_remainder_and_value;
               size_t value_size = filter->value_size;
               size_t remainder_and_value_size =
                  ctxt->remainder_size + value_size;
               routing_filter_get_remainder_and_value(
                  cfg,
                  (uint32 *)remainder_block_start,
                  pos,
                  &found_remainder_and_value,
                  remainder_and_value_size);
               uint32 found_remainder = found_remainder_and_value >> value_size;
               if (found_remainder == ctxt->remainder) {
                  uint32 value_mask  = (1UL << value_size) - 1;
                  uint16 found_value = found_remainder_and_value & value_mask;
                  platform_assert(found_value < 64);
                  found_values_int |= (1UL << found_value);
               }
            }
            *found_values = found_values_int;
            cache_unget(cc, cache_ctxt->page);
            res  = async_success;
            done = TRUE;
            break;
         }
         default:
            platform_assert(0);
      }
   } while (!done);

   return res;
}

/*
 *----------------------------------------------------------------------
 * routing_filter_zap
 *
 *      decs the ref count of the filter and destroys it if it reaches 0
 *----------------------------------------------------------------------
 */
void
routing_filter_zap(cache *cc, routing_filter *filter)
{
   // platform_error_log("electrify!!\n");
   
   if (filter->num_fingerprints == 0) {
      return;
   }

   uint64 meta_head = filter->meta_head;
   mini_unkeyed_dec_ref(cc, meta_head, PAGE_TYPE_FILTER, FALSE);
}

/*
 *----------------------------------------------------------------------
 * routing_filter_estimate_unique_keys
 *
 *      returns the expected number of unique input keys given the number of
 *      unique fingerprints in the filter.
 *----------------------------------------------------------------------
 */
uint32
routing_filter_estimate_unique_keys_from_count(routing_config *cfg,
                                               uint64          num_unique)
{
   double universe_size = 1UL << cfg->fingerprint_size;
   double unseen_fp     = universe_size - num_unique;
   /*
    * Compute the difference H_|U| - H_{|U| - #unique_fp}, where U is the fp
    * universe.
    */
   double harmonic_diff =
      log(universe_size) - log(unseen_fp)
      + 1 / 2.0 * (1 / universe_size - 1 / unseen_fp)
      - 1 / 12.0 * (1 / pow(universe_size, 2) - 1 / pow(unseen_fp, 2))
      + 1 / 120.0 * (1 / pow(universe_size, 4) - 1 / pow(unseen_fp, 4));
   uint32 estimated_input_keys = universe_size * harmonic_diff;
   return estimated_input_keys;
}

uint32
routing_filter_estimate_unique_keys(routing_filter *filter, routing_config *cfg)
{
   // platform_default_log("unique fp %u\n", filter->num_unique);
   return routing_filter_estimate_unique_keys_from_count(cfg,
                                                         filter->num_unique);
}

/*
 *----------------------------------------------------------------------
 *
 * Debug functions
 *
 *----------------------------------------------------------------------
 */

void
routing_filter_verify(cache          *cc,
                      routing_config *cfg,
                      routing_filter *filter,
                      uint16          value,
                      iterator       *itor)
{
   while (iterator_can_next(itor)) {
      key     curr_key;
      message msg;
      iterator_curr(itor, &curr_key, &msg);
      debug_assert(key_is_user_key(curr_key));
      uint64          found_values;
      platform_status rc =
         routing_filter_lookup(cc, cfg, filter, curr_key, &found_values);
      platform_assert_status_ok(rc);
      platform_assert(routing_filter_is_value_found(found_values, value));
      rc = iterator_next(itor);
      platform_assert_status_ok(rc);
   }
}

void
routing_filter_print_encoding(routing_config *cfg, routing_hdr *hdr)
{
   uint32 i;
   platform_default_log("--- Encoding: %u\n", hdr->num_remainders);
   for (i = 0; i < hdr->num_remainders + cfg->index_size; i++) {
      if (i != 0 && i % 16 == 0)
         platform_default_log(" | ");
      if (hdr->encoding[i / 8] & (1 << i % 8))
         platform_default_log("1");
      else
         platform_default_log("0");
   }
   platform_default_log("\n");
}

void
routing_filter_print_index(cache          *cc,
                           routing_config *cfg,
                           uint64          filter_addr,
                           uint32          num_indices)
{
   uint64 i;

   platform_default_log("******************************************************"
                        "**************************\n");
   platform_default_log("***   filter INDEX\n");
   platform_default_log("***   filter_addr: %lu\n", filter_addr);
   platform_default_log("------------------------------------------------------"
                        "--------------------------\n");
   uint64 page_size = cache_config_page_size(cfg->cache_cfg);
   for (i = 0; i < num_indices; i++) {
      uint64 addrs_per_page = (page_size / sizeof(uint64));
      uint64 index_addr     = filter_addr + (page_size * (i / addrs_per_page));
      page_handle *index_page =
         cache_get(cc, index_addr, TRUE, PAGE_TYPE_FILTER);
      platform_default_log("index 0x%lx: %lu\n",
                           i,
                           ((uint64 *)index_page->data)[i % addrs_per_page]);
      cache_unget(cc, index_page);
   }
}

void
routing_filter_print_remainders(routing_config *cfg,
                                routing_hdr    *hdr,
                                size_t          remainder_size,
                                size_t          value_size)
{
   uint64 i, j, start, end;
   uint64 encoding_size = (hdr->num_remainders + cfg->index_size - 1) / 8 + 1;
   uint64 header_length = encoding_size + sizeof(routing_hdr);
   platform_default_log("--- Remainders\n");
   size_t remainder_and_value_size = value_size + remainder_size;
   for (i = 0; i < cfg->index_size; i++) {
      routing_get_bucket_bounds(hdr->encoding, header_length, i, &start, &end);
      platform_default_log("0x%lx remainders:", i);
      for (j = start; j < end; j++) {
         uint32 remainder, value, remainder_and_value;
         routing_filter_get_remainder_and_value(
            cfg,
            (uint32 *)((char *)hdr + header_length),
            j,
            &remainder_and_value,
            remainder_and_value_size);
         remainder         = remainder_and_value >> value_size;
         uint32 value_mask = (1UL << value_size) - 1;
         value             = remainder_and_value & value_mask;
         platform_default_log(" 0x%x:%u", remainder, value);
      }
      platform_default_log("\n");
   }
}

void
routing_filter_print(cache *cc, routing_config *cfg, routing_filter *filter)
{
   uint64 filter_addr     = filter->addr;
   uint32 log_num_buckets = 31 - __builtin_clz(filter->num_fingerprints);
   if (log_num_buckets < cfg->log_index_size) {
      log_num_buckets = cfg->log_index_size;
   }
   uint32 log_num_indices = log_num_buckets - cfg->log_index_size;
   uint32 num_indices     = 1UL << log_num_indices;
   debug_assert(num_indices > 0);
   uint32 remainder_size = cfg->fingerprint_size - log_num_buckets;

   routing_filter_print_index(cc, cfg, filter_addr, num_indices);
   uint64 i;
   size_t value_size = filter->value_size;
   for (i = 0; i < num_indices; i++) {
      platform_default_log("----------------------------------------\n");
      platform_default_log("--- Index 0x%lx\n", i);
      page_handle *filter_page;
      routing_hdr *hdr =
         routing_get_header(cc, cfg, filter_addr, i, &filter_page);
      routing_filter_print_encoding(cfg, hdr);
      routing_filter_print_remainders(cfg, hdr, remainder_size, value_size);
      routing_unget_header(cc, filter_page);
   }
}
