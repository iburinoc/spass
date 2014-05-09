#include <stdio.h>
#include <string.h>

#include <ibcrypt/sha256.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/chacha.h>

#include <libibur/endian.h>

#include "database.h"
#include "file_db.h"
#include "spasserr.h"

static const char* const magic = "spass\0\0";

#define WRITEBLOCK 65536
#define min(a, b) ((a) > (b) ? (b) : (a))

int create_header_v00(dbfile_v00_t* dbf, uint8_t header[V00_HEADSIZE]) {
	/* offset  length  purpose */
	
	/*  0       7      magic: "spass\0\0" */
	memcpy(&header[ 0], magic, 7);
	
	/*  7       1      format version number (0x00 for this version) */
	header[ 7] = 0;
	
	/*  8       4      r (big-endian integer; must satisfy r * p < 2^30) */
	encbe32(dbf->r, &header[ 8]);
	
	/* 12       4      p (big-endian integer; must satisfy r * p < 2^30) */
	encbe32(dbf->p, &header[12]);
	
	/* 16       1      logN (scrypt parameter) */
	header[16] = dbf->logN;
	
	/* 17       7      0x00 x 7 for padding */
	memset(&header[17], 0x00, 7);
	
	/* 24      32      salt for scrypt (the parameter that changes for forced key changes) */
	memcpy(&header[24], dbf->salt, 32);
	
	/* 56       8      ctr iv (starts at 1 increments each write, when it gets to 0 force a key change) */
	encbe64(dbf->nonce, &header[56]);
	
	/* 64       8      big endian integer; length of encrypted blob */
	encbe64(serial_size_db(dbf->db), &header[64]);
	
	/* 72      24      random pad bytes */
	cs_rand(&header[72], 24);
	
	/* 96      32      HMAC-SHA256(0 .. 95) */
	HMAC_SHA256_CTX ctx;
	hmac_sha256_init(&ctx, dbf->mackey, 32);
	hmac_sha256_update(&ctx, header, 96);
	hmac_sha256_final(&ctx, &header[96]);
	
	return 0;
}

int write_db_v00(FILE* out, dbfile_v00_t* dbf)  {
	HMAC_SHA256_CTX hctx;
	CHACHA_CTX* cctx;
	uint64_t dbsize = serial_size_db(dbf->db);
	uint64_t filesize = 128 + dbsize + 32;
	uint8_t header[V00_HEADSIZE];
	uint8_t hbuf[32];
	
	size_t readlen;
	size_t offset;
	
	uint8_t* serial_db = malloc(dbsize);
	if(serial_db == NULL) {
		return ALLOC_FAIL;
	}
	
	serialize_db(dbf->db, serial_db);
	create_header_v00(dbf, header);
	
	hmac_sha256_init(&hctx, dbf->mackey, 32);
	hmac_sha256_update(&hctx, header, V00_HEADSIZE);
	
	if(fwrite(header, V00_HEADSIZE, 1, out) != 1) {
		goto err0;
	}
	
	cctx = init_chacha(dbf->ctrkey, 32, dbf->nonce);
	if(cctx == NULL) {
		goto err0;
	}
	
	stream_chacha(cctx, serial_db, serial_db, dbsize);
	free_chacha(cctx);
	
	offset = 0;
	while(offset < dbsize) {
		size_t writenum = min(WRITEBLOCK, dbsize-offset);
		if(fwrite(&serial_db[offset], writenum, 1, out) != 1) {
			if(ferror(out)) {
				fprintf(stderr, "write error");
				goto err1;	
			}
		}
		offset += writenum;
	}
	
	hmac_sha256_update(&hctx, serial_db, dbsize);
	hmac_sha256_final(&hctx, hbuf);
	
	if(fwrite(hbuf, 32, 1, out) != 1) {
		fprintf(stderr, "sad\n");
		goto err1;
	}

	free(serial_db);
	
	return SUCCESS;

err1:
	free(serial_db);
err0:
	/* failed! */
	return WRITE_ERR;
}
