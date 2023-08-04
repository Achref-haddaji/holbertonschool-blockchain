#include <stdlib.h>
#include "blockchain.h"

/**
 * blockchain_destroy - Delete an existing Blockchain along with all its Blocks
 *
 * @blockchain: Pointer to the Blockchain structure to delete
 */
void blockchain_destroy(blockchain_t *blockchain)
{
	if (blockchain == NULL)
		return;

	llist_destroy(blockchain->chain, 1, (void (*)(llist_node_t))block_destroy);
	free(blockchain);
}
