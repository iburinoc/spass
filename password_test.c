#include <ibcrypt/rand.h>

#include <libibur/test.h>

#include "password.h"

void password_tests() {
	char* name = "name";
	for(int i = 0; i < 100; i++) {
		uint8_t keybytes[32];
		AES_KEY key;
		
		uint8_t nonce[16];
		
		cs_rand(keybytes, 32);
		create_key_AES(keybytes, 256, &key);
		
		cs_rand(nonce, 16);
		
		size_t pwlen = 48 + cs_rand_int() & 0x1f;
		
		char* pw = (char*) malloc(pwlen + 1);
		
		cs_rand(pw, pwlen);
		pw[pwlen] = '\0';
		
		passw_t* pwstr = init_pw(name, pw, nonce, &key);
		
		char* outpw = dec_pw(pwstr, &key);
		
		assert_equals(pw, outpw, pwstr->passlen, "PASSWORD");
		
		free_pw(pwstr);
		free(pw);
		free(outpw);
	}
}
