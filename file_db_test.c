#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ibcrypt/scrypt.h>
#include <ibcrypt/rand.h>

#include <libibur/util.h>

#include "file_db.h"
#include "database.h"

int main() {
	char* fname = "test.spass";
	FILE* out = fopen(fname, "wb");
	dbfile_v00_t dbf;
	dbf.nonce = 1;
	dbf.r = 8;
	dbf.p = 1;
	dbf.logN = 16;
	cs_rand(dbf.salt, 32);
	uint8_t key[96];
	AES_KEY pwkey;
	scrypt("iburinoc", 8, dbf.salt, 32, (uint64_t)1 << dbf.logN, dbf.r, dbf.p, 96, key);
	memcpy(dbf.ctrkey, &key[ 0], 32);
	memcpy(dbf.mackey, &key[32], 32);
	create_key_AES(&key[64], 256, &pwkey);
	dbf.db = init_db();
	db_add_pw(dbf.db, init_pw("name", "password", 8, &pwkey));
	uint8_t pw0[44];
	serialize_pw(dbf.db->pws[0], pw0);
	printbuf(pw0, 44);
	write_db_v00(out, &dbf);
	fclose(out);
	free_db(dbf.db);
	memset(&dbf, 0x00, sizeof(dbfile_v00_t));
}
