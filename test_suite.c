#include <stdio.h>
#include <time.h>

#include <libibur/test.h>

extern void password_tests();

void (*suite[])() = {
	password_tests
};

const char* names[] = {
	"PASSWORDS"
};

int main() {
	for(int i = 0; i < sizeof(suite)/sizeof(suite[0]); i++) {
		clock_t start = clock();
		(*suite[i])();
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%s done.  %u tests completed.  %f seconds elapsed.\n", 
			names[i], count_tests(), seconds);
		reset_tests();
	}
}