#include "queue.h"

/*----- Private Queue Function Declarations -----*/

void *peek_generic(queue_t *q, queue_node_t *node);
void replace_generic(queue_t *q, void *data, int size, queue_node_t *node);

/*----- Queue Functions -----*/

// Function is responsible for creating a queue struct.
queue_t *create_queue(queue_type_t type, int max) {
    queue_t *q = (queue_t *) malloc(sizeof(queue_t));

    if (q) {
        q->head = q->tail = q->current = NULL;
        q->type = type;
        q->mutex = malloc(sizeof(pthread_mutex_t));
        pthread_mutex_init(q->mutex, NULL);
        q->full = malloc(sizeof(pthread_cond_t));
        q->empty = malloc(sizeof(pthread_cond_t));
        pthread_cond_init(q->full, NULL);
        pthread_cond_init(q->empty, NULL);
        q->count = 0;
        q->size = 0;
        q->max = max;
    }

    return q;
}

void enqueue(queue_t *q, void *data) {
    // Validate given parameters.
    if (!q || !data) {
        return;
    }

    pthread_mutex_lock(q->mutex);

    if (q->count == q->max) {
        pthread_cond_wait(q->full, q->mutex);
    }

    // Push data into queue at tail and increment count.
    queue_node_t *node = create_queue_node(data);
    if (q->head) {
        q->tail->next = node;
        q->tail = node;
        if (!q->current) q->current = node;
    } else {
        q->head = node;
        q->tail = node;
        q->current = node;
    }
    q->count++;
    pthread_cond_signal(q->empty);

    pthread_mutex_unlock(q->mutex);
}

void *dequeue(queue_t *q) {
    // Validate given parameters and return immediately if given
    // list is empty and not slated for multithreaded use.
    if (!q) return 0;

    pthread_mutex_lock(q->mutex);

    if (q->count == 0 || !q->current) pthread_cond_wait(q->empty, q->mutex);

    // Pop data off the end of the queue and decrement count.
    queue_node_t *node = q->current;
    void *data = node->data;
    if (q->type == KEEP) {
        q->current = node->next;
    } else {
        q->head = node->next;
        q->current = node->next;
        free(node);
        q->count--;
        pthread_cond_signal(q->full);
    }

    pthread_mutex_unlock(q->mutex);

    return data;
}

void *peek(queue_t *q) {
    if (!q) return 0;

    return peek_generic(q, q->current);
}

void *peek_head(queue_t *q) {
    if (!q) return 0;

    return peek_generic(q, q->head);
}

void *peek_generic(queue_t *q, queue_node_t *node) {
    pthread_mutex_lock(q->mutex);

    if (!node) pthread_cond_wait(q->empty, q->mutex);
    void *data = node->data;

    pthread_mutex_unlock(q->mutex);
    return data;
}

void *drop(queue_t *q) {
    if (!q) return 0;

    pthread_mutex_lock(q->mutex);

    if (q->count == 0) pthread_cond_wait(q->empty, q->mutex);

    queue_node_t *node = q->head;
    void *data = node->data;
    q->head = node->next;
    if (q->current == node) q->current = node->next;
    free(node);
    q->count--;
    pthread_cond_signal(q->full);

    pthread_mutex_unlock(q->mutex);

    return data;
}

void reset(queue_t *q) {
    pthread_mutex_lock(q->mutex);

    q->current = q->head;

    pthread_mutex_lock(q->mutex);
}

int caught_up(queue_t *q) {
    if (!q) return 0;
    pthread_mutex_lock(q->mutex);

    int current = q->head == q->current;

    pthread_mutex_unlock(q->mutex);
    return current;
}

void empty(queue_t *q) {
    if (!q) return;

    pthread_mutex_lock(q->mutex);

    queue_node_t *current = q->head;
    while (current) {
        queue_node_t *tmp = current->next;
        free(current);
        current = tmp;
    }
    q->head = q->tail = q->current = NULL;
    pthread_cond_signal(q->full);

    pthread_mutex_unlock(q->mutex);
}

// Function is responsible for destroying a list.
void destroy_queue(queue_t *q) {
    empty(q);
    free(q);
}

/*----- List Node Functions -----*/

// Function is responsible for creating a list node struct.
queue_node_t *create_queue_node(void *data) {
    queue_node_t *node = malloc(sizeof(queue_node_t));

    if (node) {
        node->data = data;
        node->next = node->prev = NULL;
    }

    return node;
}
