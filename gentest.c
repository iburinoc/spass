#include <stdio.h>

#include "spasserr.h"
#include "generate.h"

int main() {
	const size_t size = 128;
	char pw[size+1];
	char* const cset = dfltcset;
	
	int rc = generate(pw, size, cset);
	if(rc != SUCCESS) {
		printf("%d\n", rc);
	}
	puts(pw);
	printf("%ld\n", entropy(cset, size));
}

