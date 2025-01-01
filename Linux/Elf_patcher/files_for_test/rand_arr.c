#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void fill_random(int *arr, int size) {
    for (int i = 0; i < size; i++) {
        arr[i] = rand() % 100; // числа от 0 до 99
    }
}

void print_array(int *arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main() {
    srand(time(NULL));

    int size = 10;
    int *array = (int *)malloc(size * sizeof(int));
    if (!array) {
        printf("Memory allocation failed\n");
        return 1;
    }

    fill_random(array, size);
    printf("Generated array:\n");
    print_array(array, size);

    free(array);
    return 0;
}
