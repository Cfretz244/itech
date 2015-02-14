#ifndef LIST_H
#define LIST_H

/*----- Includes without dependencies -----*/

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

/*----- Struct Declarations -----*/

// List Node Struct.
typedef struct list_node {
    void *data;
    struct list_node *next, *prev;
} list_node;

typedef struct list {
    list_node *head, *tail;
    int count, size;
    void (*destructor)(void *);
} list;

/*----- List Functions -----*/

list *create_list(void (*destructor)(void *));
void lpush(list *lst, void *data);
void *rpop(list *lst);
void destroy_list(list *lst);

/*----- List Node Functions -----*/

list_node *create_list_node(void *data);
void destroy_list_node(list_node *node);

#endif
