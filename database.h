#ifndef SPASS_DATABASE_H
#define SPASS_DATABASE_H

#include <stdint.h>

#include "password.h"

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
uint64_t serialize_db(pwdb_t* db, uint8_t* buf);

/* add a password to the database
 * this method takes ownership of the password
 * and will free it when necessary 
 * returns 0 if successful, -1 if not */
int db_add_pw(pwdb_t* db, passw_t* pw);

/* removes the password with the given name
 * and returns 0
 * or returns -1 if not found */
int db_rem_pw(pwdb_t* db, char* name);

/* gets the password with the given name 
 * and returns it, or NULL if not found.
 * note: db maintains ownership of the password */
passw_t* db_get(pwdb_t* db, char* name);

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
