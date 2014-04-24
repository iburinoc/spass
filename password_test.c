#include <ibcrypt/rand.h>

#include <libibur/test.h>
#include <libibur/util.h>

#include "password.h"

static void serialize_tests() {
	char* name = "name";
	for(int i = 0; i < 100; i++) {
		uint8_t keybytes[32];
		AES_KEY key;
		
		uint8_t nonce[16];
		
		cs_rand(keybytes, 32);
		create_key_AES(keybytes, 256, &key);
		
		cs_rand(nonce, 16);
		
		size_t pwlen = 48 + (cs_rand_int() & 0x1f);
		
		char* pw = (char*) malloc(pwlen + 1);
		
		cs_rand(pw, pwlen);
		pw[pwlen] = '\0';
		
		passw_t* pwstr = init_pw(name, pw, pwlen, nonce, &key);
		
		uint8_t* buf = malloc(serial_size_pw(pwstr));
		
		serialize_pw(pwstr, buf);
		passw_t* npw = deserialize_pw(buf);

		char* p1 = dec_pw(pwstr, &key);
		char* p2 = dec_pw(npw, &key);
		
		assert_equals(p1, p2, pwstr->passlen, "PASSWORD SERIALIZE");
		
		free_pw(pwstr);
		free(pw);
		free(buf);
		free(npw);
		free(p1);
		free(p2);
	}
}

void initdec_tests() {
	char* name = "name";
	for(int i = 0; i < 100; i++) {
		uint8_t keybytes[32];
		AES_KEY key;
		
		uint8_t nonce[16];
		
		cs_rand(keybytes, 32);
		create_key_AES(keybytes, 256, &key);
		
		cs_rand(nonce, 16);
		
		size_t pwlen = 48 + (cs_rand_int() & 0x1f);
		
		char* pw = (char*) malloc(pwlen + 1);
		
		cs_rand(pw, pwlen);
		pw[pwlen] = '\0';
		
		passw_t* pwstr = init_pw(name, pw, pwlen, nonce, &key);
		
		char* outpw = dec_pw(pwstr, &key);
		
		assert_equals(pw, outpw, pwstr->passlen, "PASSWORD ENCRYPT");
		
		free_pw(pwstr);
		free(pw);
		free(outpw);
	}
}

void password_tests() {
	initdec_tests();
	serialize_tests();
}
