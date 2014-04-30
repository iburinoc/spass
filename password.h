#ifndef SPASS_PASSWORD_H
#define SPASS_PASSWORD_H

#define SPASS_PASSWORD_DEBUG

#include <stdint.h>

#include <ibcrypt/aes.h>

typedef struct {
	char*       name;
	uint8_t*    pass;
	uint32_t    namelen;
	uint32_t    passlen;
	uint8_t     nonce[16];
} passw_t;

/* this password should be freed with a call to free_pw and nonce should be random */
passw_t* init_pw(char* name, char* pass, uint32_t plen, AES_KEY* key);

/* deserialize a password from the stream */
passw_t* deserialize_pw(uint8_t* stream);

/* serialize the password to the buffer */
void serialize_pw(passw_t* pw, uint8_t* buf);

/* the char pointer returned must be freed by a call to free */
char* dec_pw(passw_t* pw, AES_KEY* key);

/* frees the password struct, should be used instead of free */
void free_pw(passw_t* pw);

/* return the size of this password when serialized */
uint32_t serial_size_pw(passw_t* pw);

#endif
