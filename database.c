#include <stdint.h>
#include <errno.h>

#include <libibur/endian.h>

#include "database.h"
#include "password.h"

/* initialize a new database */
pwdb_t* init() {
	pwdb_t* db;
	if((db = malloc(sizeof(pwdb_t))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	db->num = 0;
	db->pws = NULL;
	
	/* success! */
	return db;
	
err0:
	/* failed! */
	return NULL;
}

/* deserialize a database from a buffer */
pwdb_t* deserialize(uint8_t* buf, size_t len) {
	pwdb_t* db;
	uint32_t index = 0;
	
	if((db = malloc(sizeof(pwdb_t))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}

	db->num = decbe32(buf);
	if((db->pws = malloc(sizeof(passw_t*) * db->num)) == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	memset(db->pws, 0, sizeof(passw_t*) * db->num);
	
	buf += 4;
	len -= 4;
	while(len > 0 && index < db->num) {
		db->pws[index] = deserialize_pw(buf);
		if(db->pws[index] == NULL) {
			goto err2;
		}
		
		size_t sspw = serial_size_pw(db->pws[index]);
		buf += sspw;
		len -= sspw;
		index++;
	}
	
	/* buffer was not proper length */
	if(len != 0 || index != db->num) {
		errno = EINVAL;
		goto err2;
	}

	/* success! */
	return db;

err2:
	/* error in read passwords, db must be properly freed */
	free_db(db);
	
	/* avoid double free */
	goto err0;
err1:
	/* original allocation succeeded but pws alloc failed, only free db */
	free(db);
err0:
	/* failed! */
	return NULL;
}

/* frees the database as well as any passwords contained */
void free_db(pwdb_t* db) {
	uint32_t i;
	for(i = 0; i < db->num; i++) {
		if(db->pws[i] != NULL) {
			free_pw(db->pws[i]);
		}
	}
	
	/* clear info */
	memset(db->pws, 0, sizeof(passw_t*) * db->num);
	free(db->pws);
	
	memset(db, 0, sizeof(pwdb_t));
	free(db);
}

/* returns the size of this database when serialized */
uint64_t serial_size_db(pwdb_t* db) {
	uint64_t size = sizeof(uint32_t);
	uint32_t i;
	for(i = 0; i < db->num; i++) {
		size += serial_size_pw(db->pws[i]);
	}
	
	return size;
}
