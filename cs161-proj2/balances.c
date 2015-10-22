#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

/* Usage: ./balances *.blk
 * Reads in a list of block files and outputs a table of public key hashes and
 * their balance in the longest chain of blocks. In case there is more than one
 * chain of the longest length, chooses one arbitrarily. */

/* If a block has height 0, it must have this specific hash. */
const hash_output GENESIS_BLOCK_HASH = {
	0x00, 0x00, 0x00, 0x0e, 0x5a, 0xc9, 0x8c, 0x78, 0x98, 0x00, 0x70, 0x2a, 0xd2, 0xa6, 0xf3, 0xca,
	0x51, 0x0d, 0x40, 0x9d, 0x6c, 0xca, 0x89, 0x2e, 0xd1, 0xc7, 0x51, 0x98, 0xe0, 0x4b, 0xde, 0xec,
};

struct blockchain_node {
	struct blockchain_node *parent;
	struct block b;
	int is_valid;
};

/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
};

struct tree {
	struct block b;
	struct tree *kids;
	struct tree *siblings;
};

static struct tree* sortTree(struct tree *t, struct blockchain_node *node) 
{
	//struct tree *kids = (struct tree *)malloc(sizeof(struct tree));
	struct tree *siblings = (struct tree *)malloc(sizeof(struct tree));
	return siblings;
}

/* Add or subtract an amount from a linked list of balances. Call it like this:
 *   struct balance *balances = NULL;
 *
 *   // reward_tx increment.
 *   balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);
 *
 *   // normal_tx increment and decrement.
 *   balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
 *   balances = balance_add(balances, &prev_transaction.dest_pubkey, -1);
 */
static struct balance *balance_add(struct balance *balances,
	struct ecdsa_pubkey *pubkey, int amount)
{
	struct balance *p;

	for (p = balances; p != NULL; p = p->next) {
		if ((byte32_cmp(p->pubkey.x, pubkey->x) == 0)
			&& (byte32_cmp(p->pubkey.y, pubkey->y) == 0)) {
			p->balance += amount;
			return balances;
		}
	}

	/* Not found; create a new list element. */
	p = malloc(sizeof(struct balance));
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;
}

/* 
 * This is a helper function for isValidBlock 
 * Finds if there is an ancestor block's reward_tx or normal_tx variables equals hash_output 
 * If (ancestor block) normal_tx.prev_transaction_hash != h then return 0
 * Because coin has been spent and therefore the block is invalid
 * Then checks if the signature on normal_tx equals dest_pubkey by calling transaction_verify
 * If it does exist and all properties are fulfilled return 1 for valid 
 * else 0 for invalid
 * Arg blockchain_node *bn contains the block whose normal_tx.prev_transaction_hash = h
 * Arg block *b is the block we are trying to validate
 * Function should propogates up to parents to determine validatity 
 */
int findSpecificHash(struct blockchain_node *bn, struct block *b, hash_output h)
{
	/* Start by checking the block in *bn, normal_tx.prev_transaction_hash = h just in case
	 */

	/* For loop to propogate up until specific hash is found
	 * Once GENESIS_BLOCK is checked and no matches found return 0
	 */

	/* Set the blockchain_node to the parent
	 * 3. Check if no ancestor block that has the same normal_tx.prev_transaction_hash (h)
	 * If same then invalid
	 * 1. Then check if reward_tx or normal_tx in the block = h (compute with transaction_hash) 
	 * None found then invalid
	 * 2. Next use transaction_verify to check if normal_tx is valid
	 * The inputs are ancestor->(reward_tx or normal_tx) and b->normal_tx
	 * If transaction_verify  does not return 1 invalid
	 */
	return 0;

}

/* 
 * Checks all blocks and determines if it is valid. Returns 1 if it is valid, 0 if otherwise.
 * blockchain_node should come in sorted
 */
int isValidBlock(struct blockchain_node *b)
{
	/* need for loop to go through each block starting with GENESIS_BLOCK
	 */

	/* If block height is 0, then it must equal 
	 * GENESIS_BLOCK_HASH, or invalid
	 */

	/* Hash of block (use block_hash) must be smaller than TARGET_HASH. I.e must start
	 * with 24 0 bits (use hash_output_is_below_target in common.c)
	 */

	/* the height of both of the block's transactions must be equal to the 
	 * the block's height. Transaction is a struct has height variable
	 */

	/* The reward_tx.prev_transaction_hash, reward_tx.src_signature.r, 
	 * and reward_tx.src_signature.s members must be 0
	 * reward transactions are not signed and do not come  
	 * from another public key. (Use the byte32_is_zero in common.c )
	 */

	/* If normal_tx.prev_transaction_hash is 0, 
	 * vthen there is no normal transaction in this block.
	 * Else 
	 *	1. Transaction referrenced by normal_tx.prev_transaction_hash 
	  b* 	must exist as either the reward_tx or normal_tx of an ancestor 
	 * 	block. (Use the transaction_hash in transaction.c)
	 *  Will call findSpecificHash with blockchain_node containing the block in question
	 *
	 *	2. The signature (src_signature) on normal_tx must be valid 
	 *	and should be using dest_pubkey of the previous transaction
	 *	The previous transaction has the hash value normal_tx.prev_transaction_hash. 
	 *	(Use the transaction_verify in transaction.c)
	 *
	 *	3. Coin must not have already been spent: 
	 *	there must be no ancestor block that
	 *	has the same normal_tx.prev_transaction_hash.
	 *
	 *  Handled by findSpecificHash
	 */
	return 0;

}

int main(int argc, char *argv[])
{
	int i;
	struct tree *sorted_tree = malloc(sizeof(struct tree));
	//This will act as sentinel node
	struct blockchain_node *blockchain_list = malloc(sizeof(struct blockchain_node)); 
	struct blockchain_node *mini_list = malloc(sizeof(struct blockchain_node));	
	
	/* Read input block files. */
	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;
		struct blockchain_node *tempNode = malloc(sizeof(struct blockchain_node));
		
		filename = argv[i];
		// Validates whether the block is properly read
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}
		tempNode->b = b;
		mini_list->parent  = tempNode;
		mini_list = mini_list->parent;
		free(tempNode);
	}
	blockchain_list->parent = mini_list;
	
	sortTree(sorted_tree, blockchain_list);
	//struct blockchain_node *blockChainArray = malloc(sizeof(struct blockchain_node) * (i*i));
	//struct block b2;
	struct blockchain_node *iterator_node = NULL;
	for (iterator_node = blockchain_list; iterator_node != NULL; iterator_node = iterator_node->parent){
		printf("%d\n", iterator_node->b.height);
	}
	/* Organize into a tree, check validity, and output balances. */
	/* TODO */
	/* Initialize a tree using tree struct with malloc or memset*/ 
	/* Input list, and initialized tree into tree sort function to sort tree*/ 
	/* Use DFS to find all valid paths and keep track of all paths already checked (valid paths are lists of blocks?)*/
	/* For each path create a blockhain using blockchain_node struct (create function that takes list of blocks and makes blockchain?)*/
	/* Append each blockchain to a list of blockchain*/
	/* Then use  isValid each blockchain and choose the biggest valid chain*/ 


	struct balance *balances = NULL, *p, *next;
	/* Print out the list of balances. */
	
	// For loop going through block chain node for each block, and then for each transaction your calling add_balance
	// Check if normal transaction exists, if not skip. If normal_tx.prev_transaction = 0, no normal transaction
	// If normal transaction exists, add_balance(*,*,1)
				//       add_balance(*,*,-1)
	// Does normal transaction always have previous?
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	return 0;
}
