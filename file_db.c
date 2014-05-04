#include <ibcrypt/sha256.h>

#include "database.h"
#include "file_db.h"

static const char* const magic = "spass\0\0";

int create_header_v00(dbfile_v00_t* db, uint8_t header[V00_HEADSIZE]) {
	/* offset  length  purpose */
	
	/*  0       7      magic: "spass\0\0" */
	memcpy(header, magic, 7);
	header += 7;
	
	/*  7       1      format version number (0x00 for this version) */
	*header = 0;
	header += 1;
	
	/*  8       4      r (big-endian integer; must satisfy r * p < 2^30) */
	encbe32(db->r, header);
	header += 4;
	
	/* 12       4      p (big-endian integer; must satisfy r * p < 2^30) */
	encbe32(db->p, header);
	header += 4;
	
	/* 16       1      logN (scrypt parameter) */
	*header = logN;
	header += 1;
	
	/* 17       7      0x00 x 7 for padding */
	memset(header, 0x00, 7);
	header += 7;
	
	/* 24      32      salt for scrypt (the parameter that changes for forced key changes) */
	memcpy(header, db->salt, 32);
	header += 32;
	
	/* 56       8      ctr iv (starts at 1 increments each write, when it gets to 0 force a key change) */
	encbe64(db->nonce, header);
	header += 8;
	
	/* 64       8      big endian integer; length of encrypted blob */
	encbe64(serial_size_db(db->db), header);
	header += 8;
	
	/* 72      24      random pad bytes */
	cs_rand()
}

int write_db_v00(int fd, pwdb_v00_t* db)  {
	FILE* out = fopen(fd, "wb");
	
}
