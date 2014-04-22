#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "password.h"

passw_t* init_pw(char* name, char* pass, uint8_t nonce[12], AES_KEY* key) {
	passw_t* pw = (passw_t*) malloc(sizeof(passw_t));
	memset(pw, 0, sizeof(passw_t));
	
	/* name gets terminating byte */
	size_t nlen = strlen(name);
	if((pw->name = (char*) malloc(nlen + 1)) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	size_t plen = strlen(pass);
	if((pw->pass = (uint8_t*) malloc(plen)) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	pw->passlen = plen;
	
	memcpy(pw->nonce, nonce, 16);
	
	/* encrypt password in ctr mode */
	encrypt_ctr_AES((uint8_t*) pass, plen, pw->nonce, key, pw->pass);
	
	/* success! */
	return pw;
	
err0:
	/* failed! */
	free_pw(pw);
	return NULL;
}

char* dec_pw(passw_t* pw, AES_KEY* key) {
	char* decpw;
	if((decpw = (char*) malloc(pw->passlen + 1)) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	decrypt_ctr_AES(pw->pass, pw->passlen, pw->nonce, key, (uint8_t*) decpw);
		
	return decpw;
	
err0:
	/* failed! */
	return NULL;
}

void free_pw(passw_t* pw) {
	if(pw->name) {
		free(pw->name);
	}
	if(pw->pass) {
		free(pw->pass);
	}
	
	memset(pw, 0, sizeof(passw_t));
	free(pw);
	
	/* success! */
}
