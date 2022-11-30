#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define AMOUNT 64

int main(int argc, char *argv[])
{
    unsigned char aucKeysTable[96];

    aucKeysTable[95] = 36;

    srand((unsigned int)time(NULL));

    for(unsigned long long i = 0; i < 95; ++i)
    {
LOOP:
        aucKeysTable[i] = 32 + rand() % 95;

        for(unsigned long long j = 0; j < i; ++j)
        {
            if(aucKeysTable[j] == aucKeysTable[i]) goto LOOP;
        }
    }

    unsigned long long ulPasswordLength = -1;

    while(argv[1][++ulPasswordLength]);

    for(unsigned long long i = 1; i <= AMOUNT; ++i)
    {
        for(unsigned long long j = 0; argv[1][j]; ++j) argv[1][j] = aucKeysTable[argv[1][j] % 96];

        printf("One Time Password(%llu)\t%s\n", i, argv[1]);

        for(unsigned long long k = 0; k < 12; ++k)
        {
            unsigned long long ulKeyIndex, ulKeyTemp, *pulKeySwap1 = (unsigned long long*)aucKeysTable, *pulKeySwap2 = (unsigned long long*)aucKeysTable;

            if(i & 1) ulKeyIndex = argv[1][k % ulPasswordLength] % 12;

            else ulKeyIndex = rand() % 12;

            ulKeyTemp = pulKeySwap1[k];

            pulKeySwap1[k] = pulKeySwap2[ulKeyIndex];

            pulKeySwap2[ulKeyIndex] = ulKeyTemp;
        }
    }

    return 0;
}
