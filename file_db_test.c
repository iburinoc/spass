#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ibcrypt/scrypt.h>
#include <ibcrypt/rand.h>

#include <libibur/util.h>
#include <libibur/test.h>

#include "file_db.h"
#include "database.h"
#include "spasserr.h"

int write_read_test() {
	char* fname = "test.spass";
	char pw[16];
	dbfile_v00_t dbf, dbf1;
	AES_KEY pwkey;
	dbf.nonce = 1;
	dbf.r = 8;
	dbf.p = 1;
	dbf.logN = 16;
	cs_rand(dbf.salt, 32);
	cs_rand(pw, 16);
	create_key_v00(pw, 16, &dbf);
	create_key_AES(dbf.paskey, 256, &pwkey);
	dbf.db = init_db();
	db_add_pw(dbf.db, init_pw("name0", "password0", 9, &pwkey));
	db_add_pw(dbf.db, init_pw("name1", "password1", 9, &pwkey));
	db_add_pw(dbf.db, init_pw("name2", "password2", 9, &pwkey));

	FILE* out = fopen(fname, "wb");
	if(write_db_v00(out, &dbf) != SUCCESS) {
		abort();
	}
	fclose(out);

	FILE* in = fopen(fname, "rb");
	if(read_db_v00(in, &dbf1, pw, 16) != SUCCESS) {
		abort();
	}
	fclose(out);
	
	char* tmp = dec_pw(db_get_pw(dbf1.db, "name0"), &pwkey);
	assert_equals(tmp, "password0", 9, "FILE DB");
	free(tmp);
	tmp = dec_pw(db_get_pw(dbf1.db, "name2"), &pwkey);
	assert_equals(tmp, "password2", 9, "FILE DB");
	free(tmp);
	tmp = dec_pw(db_get_pw(dbf1.db, "name1"), &pwkey);
	assert_equals(tmp, "password1", 9, "FILE DB");
	free(tmp);

	assert_eq_uint(dbf1.db->num, dbf.db->num, "FILE DB NUM");

	free_db(dbf.db);
	free_db(dbf1.db);
	
	remove(fname);

	return 0;
}

void write_read_large_test() {
	char* fname = "test.spass";
	dbfile_t dbf, dbf1;
	const uint32_t num = 256, size = 1024;
	char key[256];
	char name[17];
	char pw[size];
	AES_KEY pwkey;
	uint32_t i, j;

	cs_rand(key, 255);
	key[255] = '\0';
	init_dflt_dbf_v00(&dbf, key);

	create_key_AES(dbf.paskey, 256, &pwkey);

	for(i = 0; i < num; i++) {
		name[16] = '\0';
		do {
			for(j = 0; j < 16; j++) {
				name[j] = 'a' + cs_rand_int_range(26);
			}

		} while(db_get_pw(dbf.db, name) != NULL);
		cs_rand(pw, size);
		db_add_pw(dbf.db, init_pw(name, pw, size, &pwkey));
	}
	FILE* out = fopen(fname, "wb");
	if(write_db_v00(out, &dbf) != SUCCESS) {
		abort();
	}
	fclose(out);
	FILE* in = fopen(fname, "rb");
	if(read_db_v00(in, &dbf1, key, strlen(key)) != SUCCESS) {
		abort();
	}
	fclose(out);
	char** list = db_list_names(dbf.db);

	for(i = 0; i < num; i++) {
		passw_t* pw0 = db_get_pw(dbf.db, list[i]);
		passw_t* pw1 = db_get_pw(dbf1.db, list[i]);
		if(pw0 == NULL || pw1 == NULL)  {
			assert_true(0, "LARGE DB PW LOCATE");
		}
		char* tmp0 = dec_pw(pw0, &pwkey);
		char* tmp1 = dec_pw(pw1, &pwkey);
		if(tmp0[0] == '\0' && tmp1[0] != '\0') {
			abort();
		}
		assert_equals(tmp0, tmp1, size, "LARGE DB PW EQUAL");
		free(tmp0);
		free(tmp1);
	}
	free(list);
	free_db(dbf.db);
	free_db(dbf1.db);

	remove(fname);
}

void file_db_tests() {
	write_read_test();
	write_read_large_test();
}

