#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common.h"

/* Usage: genkey FILENAME
 * Generate a key and write it to the file FILENAME. */

const unsigned char pubkey4[] = {
	0xd8 ,0xa9, 0xb4, 0xc6, 0x03, 0x83, 0x3a, 0x85, 0x86, 0xc5, 0x38, 0x9e, 0x16, 0x7d, 0x25, 0xe9, 0xe5, 0xdd, 0x33, 
	0xad, 0x3c, 0x2c, 0x95, 0xbe, 0x1c, 0x35, 0xc2, 0xdc, 0xde, 0xd6, 0x99, 0xb5
};
/* Interpret the 256 bits in buf as a private key and return an EC_KEY *. */
static EC_KEY *generate_key_from_buffer(const unsigned char buf[32])
{
	EC_KEY *key;
	BIGNUM *bn;
	int rc;

	key = NULL;
	bn = NULL;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		goto err;

	bn = BN_bin2bn(buf, 32, NULL);
	if (bn == NULL)
		goto err;

	rc = EC_KEY_set_private_key(key, bn);
	if (rc != 1)
		goto err;

	BN_free(bn);

	return key;

err:
	if (key != NULL)
		EC_KEY_free(key);
	if (bn != NULL)
		BN_free(bn);
	return NULL;
}

static EC_KEY *generate_key_bl4(void){

	unsigned char buf[32];
	int i;
	srand(1234);
	for (i = 0; i < 32; i++) {
		buf[i] = rand() & 0xff;
	}
	byte32_to_hex(buf);
	return generate_key_from_buffer(buf);
}

static EC_KEY *generate_key_bl5(void){

	unsigned char buf[32];
	int i;
	srand(time(NULL));
	for (i = 0; i < 32; i++) {
		buf[i] = rand() & 0xff;
	}
	return generate_key_from_buffer(buf);
}

/* Generate a key using EC_KEY_generate_key. */
static EC_KEY *generate_key(void)
{
	EC_KEY *key;
	int rc;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		return NULL;
	rc = EC_KEY_generate_key(key);
	if (rc != 1) {
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}

int main(int argc, char *argv[])
{
	const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];

	key = generate_key_bl5();

	if (key == NULL) {
		fprintf(stderr, "error generating key\n");
		exit(1);
	}

	rc = key_write_filename(filename, key);
	if (rc != 1) {
		fprintf(stderr, "error saving key\n");
		exit(1);
	}

	EC_KEY_free(key);

	return 0;
}
