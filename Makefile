CC=gcc
DEBUG=0
ORIGFLAGS= -c -Wall -std=gnu99

ifeq ($(DEBUG),1)
	CFLAGS=$(ORIGFLAGS) -g
	LFLAGS= 
else
	CFLAGS=$(ORIGFLAGS) -O3
	LFLAGS=
endif

LIBS=-libcrypt -lm

HEADERS=password.h database.h file_db.h
OBJECTS=password.o database.o file_db.o

MAIN_OBJECTS=$(OBJECTS) spass_main.o spass_util.o builtin.o generate.o

TEST_OBJECTS=$(OBJECTS) test_suite.o $(OBJECTS:%.o=%_test.o)

.PHONY: clean cleanall remake remaketest test

all: bin $(MAIN_OBJECTS)
	gcc $(LFLAGS) $(MAIN_OBJECTS) $(LIBS) -o bin/spass

spass: all

main: all

install: all
	cp bin/spass /usr/local/bin/spass

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

remake: clean all

remaketest: clean test
