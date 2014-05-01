CC=gcc
DEBUG=1
ORIGFLAGS= -c -Wall -std=c99

ifeq ($(DEBUG),1)
	CFLAGS=$(ORIGFLAGS) -g
	LFLAGS= 
else
	CFLAGS=$(ORIGFLAGS) -O3 -flto
	LFLAGS=-flto
endif

LIBS=-libcrypt

HEADERS=password.h database.h
OBJECTS=password.o database.o

TEST_OBJECTS=$(OBJECTS) test_suite.o $(OBJECTS:%.o=%_test.o)

.PHONY: clean cleanall remake remaketest test

test: bin $(TEST_OBJECTS)
	gcc $(LFLAGS) $(TEST_OBJECTS) $(LIBS) -o bin/test

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
