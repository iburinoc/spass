#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <libibur/endian.h>

#include <ibcrypt/aes.h>

#include "password.h"

passw_t* init_pw(char* name, char* pass, uint8_t nonce[16], AES_KEY* key) {
	passw_t* pw;
	if((pw = (passw_t*) malloc(sizeof(passw_t))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	memset(pw, 0, sizeof(passw_t));
	
	/* name gets terminating byte */
	uint32_t nlen = strlen(name);
	if((pw->name = (char*) malloc(nlen + 1)) == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	
	uint32_t plen = strlen(pass);
	if((pw->pass = (uint8_t*) malloc(plen)) == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	pw->passlen = plen;
	
	memcpy(pw->name, name, nlen + 1);
	pw->namelen = nlen;
	
	memcpy(pw->nonce, nonce, 16);
	
	/* encrypt password in ctr mode */
	encrypt_ctr_AES((uint8_t*) pass, plen, pw->nonce, key, pw->pass);
	
	/* success! */
	return pw;
	
err1:
	free_pw(pw);
err0:
	/* failed! */
	return NULL;
}

passw_t* deserialize_pw(uint8_t* stream) {
	passw_t* pw;
	if((pw = (passw_t*) malloc(sizeof(passw_t))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	memset(pw, 0, sizeof(passw_t));
	
	/* read namelen */
	pw->namelen = decbe32(stream);
	stream += 4;

	/* read passlen */
	pw->passlen = decbe32(stream);
	stream += 4;
	
	/* allocate buffer for name */
	if((pw->name = (char*) malloc(nlen + 1)) == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	
	/* allocate buffer for pass */
	if((pw->pass = (uint8_t*) malloc(plen)) == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	
	/* read nonce */
	memcpy(pw->nonce, stream, 16);
	stream += 16;
	
	/* read name */
	memcpy(pw->name, stream, pw->namelen);
	pw->name[pw->namelen] = '\0';
	stream += pw->namelen;
	
	/* read password */
	memcpy(pw->name, stream, pw->passlen);
	stream += pw->passlen;
	
	/* success! */
	return pw;
	
err1:
	free_pw(pw);
err0:
	/* failed! */
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
		/* clear data */
		memset(pw->name, 0, pw->namelen + 1);
		free(pw->name);
	}
	if(pw->pass) {
		/* clear data */
		memset(pw->pass, 0, pw->passlen);
		free(pw->pass);
	}
	
	/* clear data */
	memset(pw, 0, sizeof(passw_t));
	free(pw);
	
	/* success! */
}

/* return the size of this password when serialized */
uint32_t serial_size_pw(passw_t* pw) {
	/* sizeof(namelen) + sizeof(passlen) + sizeof(nonce) + len(name) + len(pass) */
	return serial_size_pw(pw->namelen, pw->passlen);
}

/* return the serialized size of a password with the name length and passlength */
uint32_t serial_size_pw(uint32_t nlen, uint32_t plen) {
	/* sizeof(namelen) + sizeof(passlen) + sizeof(nonce) + len(name) + len(pass) */
	return sizeof(uint32_t) * 2 + sizeof(uint8_t) * 16 + nlen + plen;
}
