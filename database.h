#ifndef SPASS_DATABASE_H
#define SPASS_DATABASE_H

#define SPASS_DATABASE_DEBUG

#include <stdint.h>
#include <stdlib.h>

#include "password.h"
#include "spasserr.h"

/* password database struct */
typedef struct {
	passw_t** pws;
	uint32_t  num;
} pwdb_t;

/* initialize new database */
pwdb_t* init_db();

/* deserializes a password database from a buffer.  may be replaced by a real stream in the future */
pwdb_t* deserialize_db(uint8_t* buf, size_t len);

/* serializes the database to the buffer.
 * buf must be at least serial_size_db(db)
 */
void serialize_db(pwdb_t* db, uint8_t* buf);

/* find the password in the sorted database and return the index
 * if not found, return 2^32-1 and set errno to EINVAL
 * NOTE: 2^32-1 response is not enough to determine a failure
 * as it is a valid index */
uint32_t find_pw(pwdb_t* db, char* name);

/* find where the password should be inserted 
 * behaviour undefined if the password is already
 * in the database */
uint32_t find_inspos(pwdb_t* db, char* name);

/* add a password to the database
 * this method takes ownership of the password
 * and will free it when necessary 
 * returns 0 if successful, 
 * apropriate error code if not */
int db_add_pw(pwdb_t* db, passw_t* pw);

/* removes the password with the given name
 * and returns 0, 
 * apropriate error code if not successful */
int db_rem_pw(pwdb_t* db, char* name);

/* gets the password with the given name 
 * and returns it, or NULL if not found.
 * note: db maintains ownership of the password */
passw_t* db_get_pw(pwdb_t* db, char* name);

/* returns a list of names in the database,
 * caller owns this list, it must free it 
 * however it does not own the names themselves 
 * (ie only free the returned pointer) */
char** db_list_names(pwdb_t* db);

/* frees the database as well as any passwords contained */
void free_db(pwdb_t* db);

/* returns the size of this database when serialized */
uint64_t serial_size_db(pwdb_t* db);

#endif
