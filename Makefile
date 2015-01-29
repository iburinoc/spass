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
LIBS=-L/usr/local/lib/ -Libcrypt/bin -libcrypt -lm
INCLUDE=-I/usr/local/include/ -Iibcrypt/bin/include/ -Iibcrypt/

HEADERS=password.h database.h file_db.h
OBJECTS=password.o database.o file_db.o

MAIN_OBJECTS=$(OBJECTS) spass_main.o spass_util.o builtin.o generate.o

TEST_OBJECTS=$(OBJECTS) test_suite.o $(OBJECTS:%.o=%_test.o)

.PHONY: clean cleanall remake remaketest test libs

all: libs bin $(MAIN_OBJECTS)
	gcc $(LFLAGS) $(MAIN_OBJECTS) $(LIBS) -o bin/spass

spass: all

main: all

install: all
	cp bin/spass /usr/local/bin/spass

test: bin $(TEST_OBJECTS)
	gcc $(LFLAGS) $(TEST_OBJECTS) $(LIBS) -o bin/test

libs:
	git submodule update --init --recursive
	$(MAKE) -C libibur
	$(MAKE) -C ibcrypt

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@

bin:
	@mkdir bin
	
clean:
	rm -rf *.o 
	
cleanall: clean
	rm -rf bin

remake: clean all

remaketest: clean test
