#include <hblk_crypto.h>

/**
 * sha256 - Computes the SHA-256 hash of a sequence of bytes
 *
 * @s: The sequence of bytes to be hashed
 * @len: The number of bytes to hash in s
 * @digest: The array to store the resulting hash
 *
 * Return: Pointer to the digest array, or NULL if digest is NULL
 */
uint8_t *sha256(int8_t const *s, size_t len, uint8_t digest
[SHA256_DIGEST_LENGTH])
{
	if (!digest)
		return (NULL);

	SHA256_CTX sha256_ctx;

	if (!SHA256_Init(&sha256_ctx))
		return (NULL);

	if (!SHA256_Update(&sha256_ctx, s, len))
		return (NULL);

	if (!SHA256_Final(digest, &sha256_ctx))
		return (NULL);

	return (digest);
}
