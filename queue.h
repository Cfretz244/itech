#ifndef QUEUE_H
#define QUEUE_H

/*----- Includes without dependencies -----*/

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

/*----- Struct Declarations -----*/

typedef enum queue_type {
    DUMP,
    KEEP
} queue_type_t;

// List Node Struct.
typedef struct queue_node {
    void *data;
    struct queue_node *next, *prev;
} queue_node_t;

typedef struct queue {
    queue_node_t *head, *tail, *current;
    int count, size, max;
    queue_type_t type;
    pthread_mutex_t *mutex;
    pthread_cond_t *full, *empty;
} queue_t;

/*----- Queue Functions -----*/

queue_t *create_queue(queue_type_t type, int max);
void enqueue(queue_t *q, void *data);
void *dequeue(queue_t *q);
void *peek(queue_t *q);
void *peek_head(queue_t *q);
void *drop(queue_t *q);
void reset(queue_t *q);
int caught_up(queue_t *q);
void empty(queue_t *q);
void block_on_empty(queue_t *q);
void unblock(queue_t *q);
void destroy_queue(queue_t *q);

/*----- Queue Node Functions -----*/

queue_node_t *create_queue_node(void *data);

#endif
