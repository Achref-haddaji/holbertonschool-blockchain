#include <stdint.h>
#include "blockchain.h"

/**
 * block_hash - Compute the hash of a Block
 *
 * @block: Pointer to the Block to be hashed
 * @hash_buf: Buffer to store the resulting hash
 *
 * Return: Pointer to hash_buf
 */
uint8_t *block_hash(
	block_t const *block, uint8_t hash_buf[SHA256_DIGEST_LENGTH])
{
	if (block == NULL || hash_buf == NULL)
		return (NULL);

	sha256((int8_t *)&block->info, sizeof(block->info), hash_buf);

	return (hash_buf);
}
