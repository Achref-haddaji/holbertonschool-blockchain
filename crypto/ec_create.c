#include <stdlib.h>
#include "hblk_crypto.h"

/**
 * ec_create - Create a new EC key pair
 *
 * Return: Pointer to the generated EC_KEY structure, or NULL upon failure
 */
EC_KEY *ec_create(void)
{
	EC_KEY *key = NULL;
	EC_GROUP *group = NULL;

    /* Create a new EC_KEY structure */
	key = EC_KEY_new();
	if (!key)
		return (NULL);

    /* Select the secp256k1 elliptic curve */
	group = EC_GROUP_new_by_curve_name(EC_CURVE);
	if (!group)
	{
		EC_KEY_free(key);
		return (NULL);
	}

    /* Generate the private key and key pair */
	if (EC_KEY_set_group(key, group) != 1 || EC_KEY_generate_key(key) != 1)
	{
		EC_KEY_free(key);
		EC_GROUP_free(group);
		return (NULL);
	}

    /* Free the memory used for the elliptic group */
	EC_GROUP_free(group);

	return (key);
}
