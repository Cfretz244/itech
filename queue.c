#include "list.h"

/*----- List Functions -----*/

// Function is responsible for creating a non-threaded list struct.
queue_t *create_queue(queue_type_t type, int max, void (*destructor)(void *)) {
    queue_t *q = (queue_t *) malloc(sizeof(queue_t));

    if (q) {
        q->head = NULL;
        q->current = q->head;
        q->tail = q->head;
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

    // Push data into list at head and increment count.
    queue_node_t *node = create_queue_node(data, size);
    if (q->head) {
        q->tail->next = node;
        q->tail = node;
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

    if (q->count == 0) pthread_cond_wait(q->empty, q->mutex);

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
            destroy_queue_node(node);
            q->count--;
            pthread_cond_signal(q->full);
        }
    } else {
        read = 0;
    }

    pthread_mutex_unlock(q->mutex);

    return read;
}

int drop(queue_t *q, void *buffer, int size) {
    if (!q) return 0;

    pthread_mutex_lock(q->mutex);

    if (q->count == 0) pthread_cond_wait(q->empty, q->mutex);

    queue_node_t *node = q->head;
    q->head = node->next;
    int read = node->size;
    memcpy(buffer, node->data, read);
    destroy_queue_node(node);
    q->count--;
    pthread_cond_signal(q->full);

    pthread_mutex_unlock(q->mutex);

    return read;
}

int queue_current_data_size(queue_t *q) {
    pthread_mutex_lock(q->mutex);

    int size = q->current->size;

    pthread_mutex_unlock(q->mutex);
    return size;
}

// Function is responsible for destroying a list.
void destroy_queue(queue_t *q) {
    // If list contains data, iterate across it, freeing nodes as we go.
    if (q->head) {
        queue_node_t *current = q->head;
        while (current) {
            queue_node_t *tmp = current;
            current = current->next;
            destroy_queue_node(tmp);
        }
    }

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
        node->next = NULL;
        node->prev = NULL;
    }

    return node;
}

// Function is responsible for destroying a list node.
void destroy_queue_node(queue_node_t *node) {
    free(node->data);
    free(node);
}
