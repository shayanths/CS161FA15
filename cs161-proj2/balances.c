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


struct tree{
  struct block b;
  struct tree* children;
  struct tree* sibling;
};

/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
};

void preorder(struct tree *p)
{
    if(p==NULL){
    	return;
    }
    printf(" %d\n",p->b.height);
    preorder(p->children);
    preorder(p->sibling);
}

struct tree* createNode(struct block b){
	struct tree* newnode = (struct tree*)malloc(sizeof(struct tree));
    newnode->children=NULL;
    newnode->sibling=NULL;
    newnode->b=b;
    return newnode;

}

int compareBlocks(struct block b1, struct block b2){
	hash_output h1;
	hash_output h2;
	block_hash(&b1, h1);
	block_hash(&b2, h2);
	int g;
	g = byte32_cmp(h1, h2);
	return g;
}

struct tree * search(struct tree * tree, struct block b){
	if(tree==NULL){
        return NULL;
	}
	int rc;
	rc = compareBlocks(b, tree->b);
    if(rc == 0){
        return tree;
    }
    struct tree* t = search(tree->children, b);
    if(t==NULL){
        t = search(tree->sibling, b);
    }
    return t;

}

struct tree * add_sibling(struct tree * n, struct block b)
{
    if ( n == NULL ){
        return NULL;
    }

    while (n->sibling){
        n = n->sibling;
    }

    return (n->sibling = createNode(b));
}

struct tree * add_child(struct tree * n, struct block b)
{
    if ( n == NULL ){
        return NULL;
    }

    if ( n->children ){
        return add_sibling(n->children, b);
    }
    else{
        return (n->children = createNode(b));
    }
}

struct tree *createTreeLevel(struct block blocks[], int size, struct tree *root) 
{
	int j;
	for (j=0; j < size-1; j++){
		if (blocks[j].height == root->b.height){
			add_sibling(root, blocks[j]);
		}else if (blocks[j].height == root->b.height+1){
			root= add_child(root, blocks[j]);
		}
	}
	return root;
}

struct tree *createTree(struct block blocks[], int size, struct tree *root, int max_height) 
{
	int i;
	int j;
	for (i = 0; i < size-1; i++){
		for(j=i+1; j < size-1; j++){
			if (blocks[j].height < blocks[i].height){
				struct block tmp;
				tmp = blocks[i];
				blocks[i] = blocks[j];
				blocks[j] = tmp;
			}
		}
	}
	root = createNode(blocks[0]);
	createTreeLevel(blocks, size, root);	
	return root;
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
int findSpecificHash(struct blockchain_node *bn, struct block b, hash_output h)
{
	/* Start by checking the block in *bn, normal_tx.prev_transaction_hash = h just in case
	 */

	/* For loop to propogate up until specific hash is found
	 * Once GENESIS_BLOCK is checked and no matches found return 0
	 */
	hash_output r_hash;
	hash_output n_hash;
	int final =0;
	while (bn->parent != NULL){
		int rc;
		int rc2;
		struct block block_ancestor = bn->parent->b;
		int spent = byte32_cmp(block_ancestor.normal_tx.prev_transaction_hash, h);
		if (spent==0){
			return 0;
		}
		transaction_hash(&block_ancestor.normal_tx, n_hash);
		transaction_hash(&block_ancestor.reward_tx, r_hash);
		rc =  byte32_cmp(h, n_hash);
		rc2 = byte32_cmp(h, r_hash);
		if (rc == 0 && final != 1){
			rc = transaction_verify(&block_ancestor.normal_tx, &b.normal_tx);
			if (rc ==1){
				final = 1;
			}
		}else{
			return 0;
		}
		if (rc2 == 0 && final != 1){
			rc2 = transaction_verify(&block_ancestor.normal_tx, &b.normal_tx);
			if (rc2 ==1){
				final = 1;
			}
		}
		bn = bn->parent;
	}
	return final;

	/* Set the blockchain_node to the parent
	 * 3. Check if no ancestor block that has the same normal_tx.prev_transaction_hash (h)
	 * If same then invalid
	 * 1. Then check if reward_tx or normal_tx in the block = h (compute with transaction_hash) 
	 * None found then invalid
	 * 2. Next use transaction_verify to check if normal_tx is valid
	 * The inputs are ancestor->(reward_tx or normal_tx) and b->normal_tx
	 * If transaction_verify  does not return 1 invalid
	 */
}

struct block findHash(struct blockchain_node *bn, struct block b, hash_output h)
{

	hash_output r_hash;
	hash_output n_hash;
	struct block block_ancestor;
	while (bn != NULL){
		int rc;
		int rc2;
		block_ancestor = bn->parent->b;
		transaction_hash(&block_ancestor.normal_tx, n_hash);
		transaction_hash(&block_ancestor.reward_tx, r_hash);
		rc =  byte32_cmp(h, n_hash);
		rc2 = byte32_cmp(h, r_hash);
		if (rc == 0){
			return block_ancestor;
		}
		if (rc2 == 0){
			return block_ancestor;
		}
		bn = bn->parent;
	}
	return block_ancestor;
}

/*return 1 if genesis block, 0 if not*/
int isGenesis(struct block *b){
	hash_output h;
	block_hash(b, h);
	int g;
	g = byte32_cmp(GENESIS_BLOCK_HASH, h);
	if (g == 0){
		return 1;
	}else{
		return 0;
	}
}

/* 
 * Checks all blocks and determines if it is valid. Returns 1 if it is valid, 0 if otherwise.
 * blockchain_node should come in sorted
 */
int isValidBlock(struct blockchain_node *bn)
{

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
	 * 	block. (Use the transaction_hash in transaction.
	 c)
	 *  Will call findSpecificHash with blockchain_node containing the block in question
	 *
	 *	2. The signature (src_signature) on normal_tx must be valid 
	 *	and should be using dest_pubkey of the previous transaction
	 *	The previous transaction has the hash value normal_tx.prev_transaction_hash. 
	 *	(Use the transaction_verify in transaction.c)
	 *
	 *	3. Coin must not have already been spent: 
	 *	there must be no ancestor block that
	 *	has t
	 he same normal_tx.prev_transaction_hash.
	 *
	 *  Handled by findSpecificHash
	 */
	int rc;
	int final;
	while (bn != NULL){	
		struct block block_ancestor = bn->parent->b;
		hash_output ancestor_hash;
		block_hash(&block_ancestor, ancestor_hash);
		rc = hash_output_is_below_target(ancestor_hash);
		if (rc ==1){
			if(block_ancestor.height == block_ancestor.normal_tx.height && block_ancestor.height == block_ancestor.reward_tx.height){
				if(byte32_is_zero(block_ancestor.reward_tx.prev_transaction_hash) && byte32_is_zero(block_ancestor.reward_tx.src_signature.r) && byte32_is_zero(block_ancestor.reward_tx.src_signature.s)){
					if (byte32_is_zero(block_ancestor.normal_tx.prev_transaction_hash) == 0){
						final = findSpecificHash(bn, block_ancestor, block_ancestor.normal_tx.prev_transaction_hash);
					}
					else{
						final = 1;
					}
				}else{
					final = 0;
					break;
				}
			} else {
				final = 0;
				break;
			}
		} else{
			final = 0;
			break;
		}
		bn = bn->parent;
	}
	if (final ==1){

		int gen;
		gen = isGenesis(&bn->b);
		if (gen==1){
			return 1;
		}else{
			return 0;
		}
	}
	return 0;

}




struct blockchain_node * dfs (struct tree * tree, int size){
	struct blockchain_node *tmp[size*size];
	struct blockchain_node *tmp_node = (struct blockchain_node * )malloc(sizeof(struct blockchain_node));
	tmp_node->b = tree->b;
	tmp_node->parent =NULL;
	tmp[0] = tmp_node;
	int i = 1;
	struct tree *child = tree->children;
	while (child != NULL){ 
		struct blockchain_node *temp2 = (struct blockchain_node * )malloc(sizeof(struct blockchain_node));
		temp2->b = child->b;
		temp2->parent = tmp_node;
		child = child->children;
		tmp_node = temp2;
		tmp[i] = tmp_node;
		i++;
	}
	int k;
	for (k=i-1; k >= 1; k--){
		int j = i+1;
		tmp_node = tmp[k];
		child = search(tree, tmp_node->b);
		struct tree * parent_child = search(tree, tmp_node->b); 
		while(child->sibling != NULL){
			child = child->sibling;
			struct blockchain_node *temp2 = (struct blockchain_node * )malloc(sizeof(struct blockchain_node));
			temp2->b = child->b;
			temp2->parent = tmp[k-1];
			tmp[j] = temp2;
			int curr_value = j;
			j++;
			if (parent_child->children != NULL){
				parent_child = parent_child->children;
				struct blockchain_node * temp4 = (struct blockchain_node * )malloc(sizeof(struct blockchain_node));
				struct blockchain_node *parent_node = tmp[curr_value];
				temp4->b = parent_child->b;
				temp4->parent = parent_node;
				tmp[j] = temp4;
				j++;	
				while (parent_child->sibling != NULL) {
					parent_child = parent_child->sibling;
					struct blockchain_node *temp2 = (struct blockchain_node * )malloc(sizeof(struct blockchain_node));
					temp2->b = parent_child->b;
					temp2->parent = parent_node;
					tmp[j] = temp2;
					j++;
				}
			}
		}
	}
	int a =0;
	struct blockchain_node * best_block = (struct blockchain_node *) malloc(sizeof(struct blockchain_node));
	struct blockchain_node * temp_block = (struct blockchain_node *) malloc(sizeof(struct blockchain_node));
	int best_height = 0;
	int height = 0;
	while(tmp[a]!=NULL){
		temp_block = tmp[a];
		if (isValidBlock(temp_block)){
			height = temp_block->b.height;
			if (height > best_height){
				best_block = temp_block;
				best_height = height;
			}
		}
		a++;
	}
	return best_block;
}


int main(int argc, char *argv[])
{
	int i;
	//struct tree *sorted_tree = malloc(sizeof(struct tree));
	//This will act as sentinel node
	/* Read input block files. */
	int max_height = 0;
	struct block blocks[argc];

	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;
		filename = argv[i];
		// Validates whether the block is properly read
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}
		blocks[i-1] = b;
		if (max_height < b.height){
			max_height = b.height;
		}	
	}

	struct tree *tree = (struct tree*) malloc(sizeof(struct tree));
	tree = createTree(blocks, argc, tree, max_height);
	struct blockchain_node * best_blockchain= (struct blockchain_node*) malloc(sizeof(struct blockchain_node));
	best_blockchain = dfs(tree, argc);
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
	while (best_blockchain != NULL){
		struct block check_block = best_blockchain->b;
		if(byte32_is_zero(check_block.normal_tx.prev_transaction_hash) == 0){
			struct block trans = findHash(best_blockchain, check_block, check_block.normal_tx.prev_transaction_hash);
			balances = balance_add(balances, &trans.normal_tx.dest_pubkey, -1);
			balances = balance_add(balances, &check_block.normal_tx.dest_pubkey, 1);	
		}
		balances = balance_add(balances, &check_block.reward_tx.dest_pubkey, 1);
		best_blockchain = best_blockchain->parent;
	}

	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	return 0;
}
