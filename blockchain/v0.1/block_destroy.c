#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "blockchain.h"

/**
 * block_destroy - Delete an existing Block
 *
 * @block: Pointer to the Block to delete
 */
void block_destroy(block_t *block)
{
	if (block == NULL)
	return;

	free(block);
}
