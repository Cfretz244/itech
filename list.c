#include "list.h"

/*----- List Functions -----*/

// Function is responsible for creating a non-threaded list struct.
list *create_list(void (*destructor)(void *)) {
    list *lst = (list *) malloc(sizeof(list));

    if (lst) {
        lst->head = NULL;
        lst->count = 0;
        lst->size = 0;
        lst->destructor = destructor;
    }

    return lst;
}

void lpush(list *lst, void *data) {
    // Validate given parameters.
    if (!lst || !data) {
        return;
    }

    // Push data into list at head and increment count.
    list_node *node = create_list_node(data);
    if (lst->head) {
        node->next = lst->head;
        lst->head->prev = node;
        lst->head = node;
    } else {
        lst->head = node;
        lst->tail = node;
    }
    lst->count++;
}

void *rpop(list *lst) {
    // Validate given parameters and return immediately if given
    // list is empty and not slated for multithreaded use.
    if (!lst || !lst->count) {
        return NULL;
    }

    // Pop data off the end of the queue and decrement count.
    list_node *node = lst->tail;
    if (lst->count > 1) {
        lst->tail = lst->tail->prev;
        lst->tail->next = NULL;
    } else {
        lst->head = NULL;
        lst->tail = NULL;
    }
    lst->count--;

    // Isolate the data, destroy the node, and return.
    void *data = node->data;
    destroy_list_node(node);
    return data;
}

// Function is responsible for destroying a list.
void destroy_list(list *lst) {
    // If list contains data, iterate across it, freeing nodes as we go.
    if (lst->head) {
        list_node *current = lst->head;
        while (current) {
            list_node *tmp = current;
            current = current->next;
            destroy_list_node(tmp);
        }
    }

    free(lst);
}

/*----- List Node Functions -----*/

// Function is responsible for creating a list node struct.
list_node *create_list_node(void *data) {
    list_node *node = (list_node *) malloc(sizeof(list_node));

    if (node) {
        node->data = data;
        node->next = NULL;
        node->prev = NULL;
    }

    return node;
}

// Function is responsible for destroying a list node.
void destroy_list_node(list_node *node) {
    free(node);
}
