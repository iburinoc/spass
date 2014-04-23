/**
 * A set of functions to facilitate testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"
#include "test.h"

static uint32_t _count = 0;

void assert_equals(const void* const _a, const void* const _b, int len, const char* const message) {
	uint8_t* a = (uint8_t*) _a;
	uint8_t* b = (uint8_t*) _b;
	for(int i = 0; i < len; i++) {
		if(a[i] != b[i]) {
			printf("%s failed\n", message);
			printbuf(a, len);
			printbuf(b, len);
			exit(-1);
		}
	}
	_count++;
}

uint32_t count_tests() {
	return _count;
}

void reset_tests() {
	_count = 0;
}
