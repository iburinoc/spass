#ifndef SPASS_TEST_H
#define SPASS_TEST_H

/**
 * A set of functions to facilitate testing
 * Header for test.c
 */

#include <stdint.h>

/* avoid namespace conflicts */
#define assert_equals spass_assert_equals
#define count_tests spass_count_tests
#define reset_tests spass_reset_tests

void assert_equals(const void* const _a, const void* const _b, int len, const char* const message);

// count completed tests
uint32_t count_tests();
void reset_tests();

#endif
