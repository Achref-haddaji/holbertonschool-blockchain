#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hblk_crypto.h"

/**
 * ec_verify - Verifies the signature
 *
 * @key: Pointer to the EC_KEY structure containing the public key
 * @msg: Pointer to the bytes to verify the signature of
 * @msglen: Number of bytes to verify
 * @sig: Pointer to the signature to be checked
 *
 * Return: 1 if the signature is valid, 0 otherwise
 */
int ec_verify(
	EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t const *sig)
{
	if (!key || !msg || !sig)
	return (0);

	return (ECDSA_verify(0, msg, msglen, sig->sig, sig->len, (EC_KEY *)key) == 1);
}
