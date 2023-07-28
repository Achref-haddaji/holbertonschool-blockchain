#include <stdlib.h>
#include "hblk_crypto.h"

/**
 * ec_create_point - Creates an EC_POINT from public key bytes
 *
 * @group: The EC_GROUP representing the elliptic curve
 * @pub: The public key to be converted
 *
 * Return: A pointer to the created EC_POINT structure upon success,
 *         or NULL upon failure
 */
static EC_POINT *ec_create_point(EC_GROUP *group, uint8_t const pub
[EC_PUB_LEN])
{
	EC_POINT *point = NULL;

	point = EC_POINT_new(group);
	if (!point)
		return (NULL);

	if (EC_POINT_oct2point(group, point, pub, EC_PUB_LEN, NULL) != 1)
	{
		EC_POINT_free(point);
		return (NULL);
	}

	return (point);
}

/**
 * ec_create_key - Creates an EC_KEY structure and sets the public key
 *
 * @group: The EC_GROUP representing the elliptic curve
 * @pub: The public key to be set
 *
 * Return: Pointer to the created EC_KEY structure upon success,
 *         or NULL upon failure
 */
static EC_KEY *ec_create_key(EC_GROUP *group, EC_POINT *pub)
{
	EC_KEY *key = NULL;

	key = EC_KEY_new();
	if (!key)
		return (NULL);

	if (EC_KEY_set_group(key, group) != 1)
	{
		EC_KEY_free(key);
		return (NULL);
	}

	if (EC_KEY_set_public_key(key, pub) != 1)
	{
		EC_KEY_free(key);
		return (NULL);
	}

	return (key);
}

/**
 * ec_from_pub - Creates an EC_KEY structure given a public key
 *
 * @pub: The public key to be converted
 *
 * Return: Pointer to the created EC_KEY structure upon success,
 *         or NULL upon failure
 */
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN])
{
	EC_KEY *key = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;

	if (!pub)
		return (NULL);

	key = EC_KEY_new();
	if (!key)
		return (NULL);

	group = EC_GROUP_new_by_curve_name(EC_CURVE);
	if (!group)
	{
		EC_KEY_free(key);
		return (NULL);
	}

	point = ec_create_point(group, pub);
	if (!point)
	{
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return (NULL);
	}

	key = ec_create_key(group, point);
	if (!key)
	{
		EC_POINT_free(point);
		EC_GROUP_free(group);
		return (NULL);
	}

	EC_POINT_free(point);
	EC_GROUP_free(group);

	return (key);
}
