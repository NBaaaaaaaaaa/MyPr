#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main() {
    // Инициализируем генератор случайных чисел текущим временем
    srand(time(NULL));

    printf("50 случайных чисел:\n");

    // Генерируем и выводим 50 случайных чисел
    for (int i = 0; i < 50; i++) {
        int random_number = rand(); // Генерация случайного числа
        printf("%d\n", random_number);
        sleep(1);
    }

    return 0;
}