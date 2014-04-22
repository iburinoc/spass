#ifndef SPASS_PASSWORD_H
#define SPASS_PASSWORD_H

#include <stdint.h>

#include <ibcrypt/aes.h>

typedef struct {
	char*       name;
	uint8_t*    pass;
	size_t      passlen;
	uint8_t     nonce[16];
} passw_t;

/* this password should be freed with a call to free_pw and nonce should be random */
passw_t* init_pw(char* name, char* pass, uint8_t nonce[16], AES_KEY* key);

/* the char pointer returned must be freed by a call to free */
char* dec_pw(passw_t* pw, AES_KEY* key);

/* frees the password struct, should be used instead of free */
void free_pw(passw_t* pw);

#endif
