#include <stdio.h>
#include <unistd.h>

void main(){
    for (int i = 0; i < 50; i++) {
        printf("%d - hello world\n", i);
        sleep(1);
    }

    return;
}