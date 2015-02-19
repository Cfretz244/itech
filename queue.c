#include "queue.h"

/*----- Private Queue Function Declarations -----*/

int peek_generic(queue_t *q, void *data, int size, queue_node_t *node);
void replace_generic(queue_t *q, void *data, int size, queue_node_t *node);

/*----- Queue Functions -----*/

// Function is responsible for creating a queue struct.
queue_t *create_queue(queue_type_t type, int max, void (*destructor)(void *)) {
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
        q->destructor = destructor;
    }

    return q;
}

void enqueue(queue_t *q, void *data, int size) {
    // Validate given parameters.
    if (!q || !data) {
        return;
    }

    pthread_mutex_lock(q->mutex);

    if (q->count == q->max) {
        pthread_cond_wait(q->full, q->mutex);
    }

    // Push data into queue at tail and increment count.
    queue_node_t *node = create_queue_node(data, size);
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

int dequeue(queue_t *q, void *buffer, int size) {
    // Validate given parameters and return immediately if given
    // list is empty and not slated for multithreaded use.
    if (!q) return 0;

    int read;
    pthread_mutex_lock(q->mutex);

    if (q->count == 0 || !q->current) pthread_cond_wait(q->empty, q->mutex);

    // Pop data off the end of the queue and decrement count.
    queue_node_t *node = q->current;
    if (node->size <= size) {
        read = node->size;
        memcpy(buffer, node->data, read);
        if (q->type == KEEP) {
            q->current = node->next;
        } else {
            q->head = node->next;
            q->current = node->next;
            destroy_queue_node(node, q->destructor);
            q->count--;
            pthread_cond_signal(q->full);
        }
    } else {
        read = 0;
    }

    pthread_mutex_unlock(q->mutex);

    return read;
}

int peek(queue_t *q, void *data, int size) {
    if (!q) return 0;

    return peek_generic(q, data, size, q->current);
}

int peek_head(queue_t *q, void *data, int size) {
    if (!q) return 0;

    return peek_generic(q, data, size, q->head);
}

int peek_generic(queue_t *q, void *data, int size, queue_node_t *node) {
    int read;
    pthread_mutex_lock(q->mutex);

    if (!node) pthread_cond_wait(q->empty, q->mutex);

    if (node && size >= node->size) {
        memcpy(data, node->data, node->size);
    } else {
        read = 0;
    }

    pthread_mutex_unlock(q->mutex);
    return read;
}

void replace(queue_t *q, void *data, int size) {
    if (!q) return;

    replace_generic(q, data, size, q->current);
}

void replace_head(queue_t *q, void *data, int size) {
    if (!q) return;

    replace_generic(q, data, size, q->head);
}

void replace_generic(queue_t *q, void *data, int size, queue_node_t *node) {
    pthread_mutex_lock(q->mutex);

    if (node->size >= size) {
        memcpy(node->data, data, size);
        node->size = size;
    } else {
        free(node->data);
        node->data = malloc(size);
        memcpy(node->data, data, size);
        node->size = size;
    }

    pthread_mutex_unlock(q->mutex);
}

int drop(queue_t *q, void *buffer, int size) {
    if (!q) return 0;

    pthread_mutex_lock(q->mutex);

    if (q->count == 0) pthread_cond_wait(q->empty, q->mutex);

    queue_node_t *node = q->head;
    q->head = node->next;
    if (q->current == node) q->current = node->next;
    int read = node->size;
    if (buffer) memcpy(buffer, node->data, read);
    destroy_queue_node(node, q->destructor);
    q->count--;
    pthread_cond_signal(q->full);

    pthread_mutex_unlock(q->mutex);

    return read;
}

int caught_up(queue_t *q) {
    if (!q) return 0;
    pthread_mutex_lock(q->mutex);

    int current = q->head == q->current;

    pthread_mutex_unlock(q->mutex);
    return current;
}

int queue_head_data_size(queue_t *q) {
    if (!q) return 0;
    pthread_mutex_lock(q->mutex);

    int size = q->head->size;

    pthread_mutex_unlock(q->mutex);
    return size;
}

int queue_current_data_size(queue_t *q) {
    if (!q) return 0;
    pthread_mutex_lock(q->mutex);

    int size = q->current->size;

    pthread_mutex_unlock(q->mutex);
    return size;
}

void empty(queue_t *q) {
    if (!q) return;

    pthread_mutex_lock(q->mutex);

    queue_node_t *current = q->head;
    while (current) {
        queue_node_t *tmp = current->next;
        destroy_queue_node(current, q->destructor);
        current = tmp;
    }
    q->head = q->tail = q->current = NULL;

    pthread_mutex_unlock(q->mutex);
}

// Function is responsible for destroying a list.
void destroy_queue(queue_t *q) {
    empty(q);
    free(q);
}

/*----- List Node Functions -----*/

// Function is responsible for creating a list node struct.
queue_node_t *create_queue_node(void *data, int size) {
    queue_node_t *node = malloc(sizeof(queue_node_t));

    if (node) {
        node->data = malloc(size);
        memcpy(node->data, data, size);
        node->size = size;
        node->next = node->prev = NULL;
    }

    return node;
}

// Function is responsible for destroying a list node.
void destroy_queue_node(queue_node_t *node, void (*destructor)(void *)) {
    destructor(node->data);
    free(node);
}
