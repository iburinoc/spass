#ifndef SPASS_FILE_OP_H
#define SPASS_FILE_OP_H

#include "database.h"

typedef struct {
	pwdb_t* db;
	char* filename;
	uint64_t nonce; /* when this reaches 0, force a key reset */
	uint32_t r;
	uint32_t p;
	uint8_t logN;
	uint8_t salt[32];
	/* very sensitive... */
	uint8_t ctrkey[32];
	uint8_t mackey[32];
} dbfile_v00_t;

#define V00_HEADSIZE 128

int create_header_v00(dbfile_v00_t* db, uint8_t header[V00_HEADSIZE]);

int write_db_v00(int fd, dbfile_v00_t* db);

#endif
