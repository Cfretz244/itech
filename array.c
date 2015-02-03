#include "array.h"

/*----- Array Functions -----*/

// Function is responsible for creating an array struct.
array *create_array() {
    array *arr = (array *) malloc(sizeof(array));

    if (arr) {
        // Use calloc to allocate storage space to allow for explicit NULL checks.
        arr->storage = (void **) calloc(INIT_ARRAY_LENGTH, sizeof(void **));
        arr->size = INIT_ARRAY_LENGTH;
        arr->count = 0;
    }

    return arr;
}

// Function is responsible for inserting the given data at the specified
// index. If the underlying array is not large enough, apply exponential reallocation
// until it is.
bool insert(array *arr, int index, void *data) {
    // Check that array is large enough.
    while (index >= arr->size) {
        // Reallocate array.
        int start_size = arr->size;
        arr->size *= 2;
        void **temp = (void **) realloc(arr->storage, sizeof(void *) * arr->size);
        if (temp) {
            // Allocation succeeded. Initialize all new memory to zero to allow for
            // explicit NULL checks.
            memset(&temp[start_size], 0, (arr->size - start_size) * sizeof(void *));
            arr->storage = temp;
        } else {
            // We are out of memory, and the insertion is impossible.
            return false;
        }
    }

    // Check to make sure given index is unoccupied.
    if (!arr->storage[index]) {
        arr->storage[index] = data;
        arr->count++;
        return true;
    } else {
        // Index is occupied. Abort insertion.
        return false;
    }
}

// Function is responsible for getting the data at a specific index. Invalid
// indexes return NULL.
void *retrieve(array *arr, int index) {
    if (index < arr->size && index >= 0) {
        return arr->storage[index];
    } else {
        return NULL;
    }
}

// Function empties a specific index and returns the contained data.
void *clear(array *arr, int index) {
    if (index < arr->size) {
        void *temp = arr->storage[index];
        arr->storage[index] = NULL;
        arr->count--;
        return temp;
    } else {
        return NULL;
    }
}

// Function is responsible for destroying an array struct and all associated
// data.
void destroy_array(array *arr, void (*destruct) (void *)) {
    for (int i = 0; i < arr->size; i++) {
        if (arr->storage[i]) {
            destruct(arr->storage[i]);
        }
    }

    free(arr);
}
