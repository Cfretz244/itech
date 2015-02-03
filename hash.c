#include "hash.h"

/*----- Hash Functions -----*/

// Function handles creation of a hash struct.
hash *create_hash(void (*destruct) (void *)) {
    hash *table = (hash *) malloc(sizeof(hash));

    if (table) {
        // Allocate table with calloc to allow for NULL checks.
        table->data = (hash_node **) calloc(START_SIZE, sizeof(hash_node *));
        table->destruct = destruct;
        table->count = 0;
        table->size = START_SIZE;
    }

    return table;
}

// Function handles creation of a hash value for a given string.
int hash_key(char *key, int size) {
    int proto_hash = 0;
    for (int i = 0; i < strlen(key); i++) {
        proto_hash += (int) key[i];
    }
    return proto_hash % size;
}

// Function handles the rehash process encountered when a hash reaches
// 80% capacity.
void rehash(hash *table) {
    // Allocate new table with calloc to allow for NULL checks.
    hash_node **old_data = table->data;
    hash_node **new_data = (hash_node **) calloc(table->size * 2, sizeof(hash_node *));

    // Copy all previous data into new, larger, hash.
    for(int i = 0; i < table->size; i++) {
        hash_node *current = old_data[i];
        while (current) {
            hash_node *tmp = current->next;
            current->next = NULL;

            // Calculate new hash value and insert.
            int hash = hash_key(current->key, table->size * 2);
            if (new_data[hash]) {
                insert_hash_node(new_data[hash], current);
            } else {
                new_data[hash] = current;
            }
            current = tmp;
        }
    }

    // Update hash struct with changes.
    table->data = new_data;
    table->size *= 2;
    free(old_data);
}

// Insert data into a hash for a specific key.
bool put(hash *table, char *key, void *data) {
    // Verify parameters.
    if (!table || !key || !data) {
        return false;
    }

    // Check if table needs a rehash.
    if (table->count / (float) table->size > 0.8) {
        rehash(table);
    }

    // Generate hash value and insert.
    int hash = hash_key(key, table->size);

    // Verify that table does not already contain given key.
    if (table->data[hash]) {
        // Check if we're dealing with a hash collision, or a repeat
        // key.
        if (!find_hash_node(table->data[hash], key)) {
            // Data is new.
            hash_node *node = create_hash_node(key, data);
            insert_hash_node(table->data[hash], node);
            table->count++;
            return true;
        } else {
            // Key already exists in table.
            return false;
        }
    } else {
        // Insert new data into table.
        hash_node *node = create_hash_node(key, data);
        table->data[hash] = node;
        table->count++;
        return true;
    }
}

// Function handles getting data out of a hash for a specific key.
void *get(hash *table, char *key) {
    // Verify parameters.
    if (!table || !table->count || !key) {
        return NULL;
    }

    // Generate hash value and find data.
    int hash = hash_key(key, table->size);
    hash_node *found = find_hash_node(table->data[hash], key);

    if (found) {
        return found->data;
    } else {
        return NULL;
    }

}

// Handle removal of a key from hash. Although never actually called in the
// project, it seemed dishonest not to include it.
bool drop(hash *table, char *key) {
    // Verify parameters.
    if (!table || table->count == 0 || !key) {
        return false;
    }

    // Generate hash value and find data.
    int hash = hash_key(key, table->size);
    if (table->data[hash]) {
        if (find_hash_node(table->data[hash], key)) {
            // Remove appropriate data.
            table->data[hash] = remove_hash_node(table->data[hash], key, table->destruct);
            table->count--;
            return true;
        } else {
            // Key does not exist in table.
            return false;
        }
    } else {
        // Key does not exist in table.
        return false;
    }
}

// Function handles the enumeration of all keys currently stored in hash.
// Returns said keys in any order.
char **get_keys(hash *table) {
    if (!table) {
        return NULL;
    }

    // Allocate key array.
    int current = 0;
    char **keys = (char **) malloc(sizeof(char *) * table->count);

    // Iterate across each array index, and each hash_node chain.
    for (int i = 0; i < table->size; i++) {
        if (table->data[i]) {
            for (hash_node *tmp = table->data[i]; tmp; tmp = tmp->next) {
                keys[current] = tmp->key;
                current++;
            }
        }
    }

    return keys;
}

// Function handles the destruction of hash struct.
void destroy_hash(hash *table) {
    // Verify parameters.
    if (!table) {
        return;
    }

    if (table->count > 0) {
        // Destroy all necessary data.
        for (int i = 0; i < table->size; i++) {
            hash_node *node = table->data[i];
            if (node) {
                destroy_hash_chain(node, table->destruct);
            }
        }
    }
    free(table->data);
    free(table);
}

/*---- Hash Node Functions ----*/

// Function handles the creation of a hash_node struct.
hash_node *create_hash_node(char *key, void *data) {
    hash_node *node = (hash_node *) malloc(sizeof(hash_node));

    if (node) {
        // Copy given string so it can't be freed out from under us.
        char *intern_key = (char *) malloc(sizeof(char) * (strlen(key) + 1));
        if (intern_key) {
            strcpy(intern_key, key);
            node->key = intern_key;
            node->data = data;
            node->next = NULL;
        } else {
            // Key could not be copied. Continued initialization impossible.
            free(node);
            node = NULL;
        }
    }

    return node;
}

// Function handles inserting a hash node into a linked list of hash nodes.
bool insert_hash_node(hash_node *head, hash_node *insert) {
    // Validate paramaters and insert if the list doesn't already contain
    // the given node.
    if (head && insert) {
        for (hash_node *current = head; current; current = current->next) {
            if (!strcmp(insert->key, current->key)) {
                return false;
            } else if(!current->next) {
                current->next = insert;
                return true;
            }
        }
        return false;
    } else {
        return false;
    }
}

// Function handles finding hash_node with a specific key in a linked list
// of nodes.
hash_node *find_hash_node(hash_node *head, char *key) {
    // Validate parameters and search.
    if (head && key) {
        for (hash_node *current = head; current; current = current->next) {
            if (!strcmp(current->key, key)) {
                // Found it.
                return current;
            }
        }
        // Didn't find it.
        return NULL;
    } else {
        return NULL;
    }
}

// Function handles removing a hash_node specified by key from a linked
// list of nodes.
hash_node *remove_hash_node(hash_node *head, char *key, void (*destruct) (void *)) {
    // Validate parameters and search.
    if (head && key && destruct) {
        hash_node *prev = NULL;
        for (hash_node *current = head; current; current = current->next) {
            if (!strcmp(current->key, key)) {
                // Found it.
                if (prev) {
                    // Normal case.
                    hash_node *tmp = current->next;
                    destruct(current);
                    prev->next = tmp;
                    return head;
                } else {
                    // We need to remove the head.
                    destruct(head);
                    return head->next;
                }
            }
            prev = current;
        }
    }
    return head;
}

// Function handles the destruction of an entire linked list of hash_nodes.
void destroy_hash_chain(hash_node *head, void (*destruct) (void *)) {
    // Iterate across list and destroy each node we come to.
    while (head) {
        hash_node *tmp = head;
        head = head->next;
        destroy_hash_node(tmp, destruct);
    }
}

// Function handles the destruction of a specific hash_node struct.
void destroy_hash_node(hash_node *node, void (*destruct) (void *)) {
    free(node->key);
    destruct(node->data);
    free(node);
}
