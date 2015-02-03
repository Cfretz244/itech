#ifndef HASH
#define HASH

/*----- Includes without dependencies -----*/

#include <stdlib.h>
#include <string.h>
#include "definitions.h"

/*----- Numerical Constants -----*/

#define START_SIZE 10

/*----- Struct Declarations -----*/

// Node struct used for chaining hash collision resolution.
typedef struct hash_node {
    char *key;
    void *data;
    struct hash_node *next;
} hash_node;

// Struct represents a basic hashtable.
typedef struct hash {
    hash_node **data;
    void (*destruct) (void *);
    int count;
    int size;
} hash;

/*----- Hash Functions -----*/

hash *create_hash(void (*destruct) (void *));
bool put(hash *table, char *key, void *data);
void *get(hash *table, char *key);
char **get_keys(hash *table);
bool drop(hash *table, char *key);
void destroy_hash(hash *table);

/*----- Hash Node Functions -----*/

hash_node *create_hash_node(char *key, void *data);
bool insert_hash_node(hash_node *head, hash_node *insert);
hash_node *find_hash_node(hash_node *head, char *key);
hash_node *remove_hash_node(hash_node *head, char *key, void (*destruct) (void *));
void destroy_hash_chain(hash_node *head, void (*destruct) (void *));
void destroy_hash_node(hash_node *node, void (*destruct) (void *));

#endif
