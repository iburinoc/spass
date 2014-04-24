CC=gcc
DEBUG=0
ORIGFLAGS= -c -Wall -std=c99

ifeq ($(DEBUG),1)
	CFLAGS=$(ORIGFLAGS) -g
else
	CFLAGS=$(ORIGFLAGS) -O4
endif

LIBS=-libcrypt

HEADERS=password.h
OBJECTS=password.o

TEST_OBJECTS=$(OBJECTS) test_suite.o password_test.o

.PHONY: clean cleanall remake remaketest test

test: bin $(TEST_OBJECTS)
	gcc $(TEST_OBJECTS) $(LIBS) -o bin/test

.c.o:
	$(CC) $(CFLAGS) $< -o $@

bin:
	@mkdir bin
	
clean:
	rm -rf *.o 
	
cleanall: clean
	rm -rf bin

remake: clean

remaketest: clean test
