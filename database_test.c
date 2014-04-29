#include <libibur/test.h>

#include <ibcrypt/aes.h>
#include <ibcrypt/rand.h>

#include "spasserr.h"
#include "database.h"

void database_search_tests() {
	char* password = "password";
	uint8_t kbytes[32];
	AES_KEY key;
	
	cs_rand(kbytes, 32);
	create_key_AES(kbytes, 256, &key);
	
	pwdb_t* db = init_db();

	char n[2];
	n[1] = '\0';
	for(int i = 0; i < 26; i++) {
		n[0] = (char) (65 + i);
		
		passw_t* pw = init_pw(n, password, 8, &key);
		db_add_pw(db, pw);
	}
	
	for(int i = 0; i < 26; i++) {
		n[0] = (char) (65 + i);
		
		passw_t* pw = db_get_pw(db, n);
		char* decpw = dec_pw(pw, &key);
		assert_equals(decpw, password, strlen(password)+1, "DATABASE");
		
		assert_true(db_add_pw(db, pw) == PW_EXISTS, "DATABASE");
	}
	
	free_db(db);
}

void database_tests() {
	database_search_tests();
}