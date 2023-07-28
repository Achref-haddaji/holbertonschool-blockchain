#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hblk_crypto.h"

/**
 * ec_sign - Signs a given set of bytes using a given EC_KEY private key
 *
 * @key: Pointer to the EC_KEY structure containing the private key
 * @msg: Pointer to the bytes to be signed
 * @msglen: Number of bytes to sign
 * @sig: Address at which to store the signature
 *
 * Return: Pointer to the signature buffer
 */
uint8_t *ec_sign(
	EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t *sig)
{
	if (!key || !msg || !sig)
		return (NULL);

	if (!ECDSA_sign(0, msg, msglen, sig->sig, (unsigned int *)
	&(sig->len), (EC_KEY *)key))
		return (NULL);

	return (sig->sig);
}
