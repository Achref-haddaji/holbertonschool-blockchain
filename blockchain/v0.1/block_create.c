#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "blockchain.h"

/**
 * block_create - Create a new Block structure and initialize it
 *
 * @prev: Pointer to the previous Block in the Blockchain
 * @data: Points to a memory area to duplicate in the Block's data
 * @data_len: Number of bytes to duplicate in data
 *
 * Return: Pointer to the allocated Block, or NULL on failure
 */
block_t *block_create(
	block_t const *prev, int8_t const *data, uint32_t data_len)
{
	block_t *block = malloc(sizeof(block_t));

	if (block == NULL)
		return (NULL);

	block->info.index = (prev != NULL) ? prev->info.index + 1 : 0;
	block->info.difficulty = 0;
	block->info.timestamp = time(NULL);
	block->info.nonce = 0;

	if (prev != NULL)
		memcpy(block->info.prev_hash, prev->hash, SHA256_DIGEST_LENGTH);
	else
		memset(block->info.prev_hash, 0, SHA256_DIGEST_LENGTH);

	memset(block->hash, 0, SHA256_DIGEST_LENGTH);

	if (data_len > BLOCKCHAIN_DATA_MAX)
		data_len = BLOCKCHAIN_DATA_MAX;

	memcpy(block->data.buffer, data, data_len);
	block->data.len = data_len;

	return (block);
}
