#ifndef SPASS_DATABASE_H
#define SPASS_DATABASE_H

#include <stdint.h>

#include "password.h"

/* password database struct */
typedef struct {
	passw_t** pws;
	uint32_t  num;
} pwdb_t;

/* deserializes a password database from a buffer.  may be replaced by a real stream in the future */
pwdb_t* deserialize(uint8_t* buf, size_t len);

/* frees the database as well as any passwords contained */
void free_db(pwdb_t* db);

/* returns the size of this database when serialized */
uint64_t serial_size_db(pwdb_t* db);

#endif
