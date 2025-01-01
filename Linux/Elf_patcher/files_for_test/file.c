#include <unistd.h>

int main() {
    const char *message = "Hello, world!\n";
    write(1, message, 14); // Пишем в stdout
    return 0;
}
