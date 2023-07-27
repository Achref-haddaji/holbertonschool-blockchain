#include <stdlib.h>
#include "hblk_crypto.h"

/**
 * ec_from_pub - Creates an EC_KEY structure given a public key
 *
 * @pub: The public key to be converted
 *
 * Return: Pointer to the created EC_KEY structure upon success, or NULL upon failure
 */
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN])
{
	EC_KEY *key = NULL;
	EC_POINT *point = NULL;
	EC_GROUP *group = NULL;

	if (!pub)
		return (NULL);

	/* Create a new EC_KEY structure */
	key = EC_KEY_new();
	if (!key)
		return (NULL);

	/* Set the EC_KEY to use the secp256k1 curve */
	group = EC_GROUP_new_by_curve_name(EC_CURVE);
	if (!group)
	{
		EC_KEY_free(key);
		return (NULL);
	}

	if (EC_KEY_set_group(key, group) != 1)
	{
		EC_KEY_free(key);
		EC_GROUP_free(group);
		return (NULL);
	}

	/* Create a new EC_POINT structure from the given public key */
	point = EC_POINT_new(group);
	if (!point)
	{
		EC_KEY_free(key);
		EC_GROUP_free(group);
		return (NULL);
	}

	if (EC_POINT_oct2point(group, point, pub, EC_PUB_LEN, NULL) != 1)
	{
		EC_KEY_free(key);
		EC_GROUP_free(group);
		EC_POINT_free(point);
		return (NULL);
	}

	/* Set the public key in the EC_KEY structure */
	if (EC_KEY_set_public_key(key, point) != 1)
	{
		EC_KEY_free(key);
		EC_GROUP_free(group);
		EC_POINT_free(point);
		return (NULL);
	}

	/* Free memory for the EC_POINT and EC_GROUP structures */
	EC_POINT_free(point);
	EC_GROUP_free(group);

	return (key);
}
