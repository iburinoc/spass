#ifndef SPASS_FILE_OP_H
#define SPASS_FILE_OP_H

#include <stdio.h>

#include "database.h"

//#define SPASS_FILE_DB_TEST

typedef struct {
	pwdb_t* db;
	uint64_t nonce; /* when this reaches 0, force a key reset */
	uint32_t r;
	uint32_t p;
	uint8_t logN;
	uint8_t salt[32];
	/* very sensitive... */
	uint8_t ctrkey[32];
	uint8_t mackey[32];
	uint8_t paskey[32];

	/* flag, if not modified it does not need to be written out */
	int modified;
} dbfile_v00_t;

typedef dbfile_v00_t dbfile_t;

#define V00_HEADSIZE 128

int init_dflt_dbf_v00(dbfile_v00_t* dbf, char* password);

int write_db_v00(FILE* out, dbfile_v00_t* dbf);

int read_db_v00(FILE* in, dbfile_v00_t* dbf, char* password, uint32_t plen);

int create_key_v00(char* pw, uint32_t pwlen, dbfile_v00_t* dbf);

int resalt_dbf_v00(dbfile_v00_t* dbf, char* password);

void clear_dbf_v00(dbfile_v00_t* dbf);

#endif

