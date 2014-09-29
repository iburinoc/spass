#include <string.h>
#include <math.h>

#include <ibcrypt/rand.h>

#include "generate.h"
#include "password.h"
#include "spasserr.h"

char* const dfltcset = "a-zA-Z0-9!@#$%^&*\\-_";

int expand_charset(char** ecset, char* cset) {
	/* array of activated characters */
	int on[256];
	memset(on, 0x00, sizeof(int) * 256);

	size_t len = strlen(cset);
	if(len > MAX_CHARSET_LEN) {
		return TOO_LONG;
	}

	char* out = malloc(MAX_CHARSET_LEN + 1);
	if(out == NULL) {
		return ALLOC_FAIL;
	}

	size_t i;
	int escaped = 0;

	for(i = 0; i < len; i++) {
		if(escaped) {
			on[(int) cset[i]] = 1;
			escaped = 0;
		} else {
			if(cset[i] == '\\') {
				escaped = 1;
			} else {
				on[(int) cset[i]] = 1;
			}
		}
		if(!escaped && i + 2 < len && cset[i+1] == '-') {
			size_t j;
			for(j = cset[i]; j <= cset[i+2]; j++) {
				on[j] = 1;
			}
			i += 2;
		}
	}

	size_t pos = 0;
	for(i = 0; i < 256; i++) {
		if(on[i]) {
			if(pos == MAX_CHARSET_LEN) {
				free(out);
				return TOO_LONG;
			}

			out[pos++] = (char) i;
		}
	}

	out[pos] = '\0';

	*ecset = out;

	return SUCCESS;
}

/* pw must be a buffer of size at least len + 1 */
int generate(char* pw, size_t len, char* cset) {
	if(len > MAX_PASSLEN) {
		return TOO_LONG;
	}

	int rc = expand_charset(&cset, cset);
	if(rc != SUCCESS) {
		return rc;
	}

	size_t csetl = strlen(cset);
	size_t i;
	for(i = 0; i < len; i++) {
		pw[i] = cset[cs_rand_int_range(csetl)];
	}

	pw[len] = '\0';

	free(cset);

	return SUCCESS;
}

long entropy(char* cset, int len) {
	int rc = expand_charset(&cset, cset);
	if(rc != SUCCESS) {
		return 0;
	}

	int ent = (int) (log((double)strlen(cset))/log(2) * len);
	free(cset);

	return ent;
}

