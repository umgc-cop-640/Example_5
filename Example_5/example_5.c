#include <wchar.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

void printLine(const char* line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}
void printHexCharLine(char charHex)
{
    printf("%02x\n", charHex);
}
void CWE190_Integer_Overflow__char_fscanf_add_01_bad()
{
    char data[5];
   
    /* POTENTIAL FLAW: Use a value input from the console */
    fgets(data, 10, stdin);
    {
        /* POTENTIAL FLAW: Adding 1 to data could cause an overflow */
        char result = data + 1;
        printHexCharLine(result);
    }
}
void CWE126_Buffer_Overread__char_alloca_loop_01_bad()
{
    char* data;
    char* dataBadBuffer = (char*)_alloca(50 * sizeof(char));
    char* dataGoodBuffer = (char*)_alloca(100 * sizeof(char));
    memset(dataBadBuffer, 'A', 50 - 1); /* fill with 'A's */
    dataBadBuffer[50 - 1] = '\0'; /* null terminate */
    memset(dataGoodBuffer, 'A', 100 - 1); /* fill with 'A's */
    dataGoodBuffer[100 - 1] = '\0'; /* null terminate */
    /* FLAW: Set data pointer to a small buffer */
    data = dataBadBuffer;
    {
        size_t i, destLen;
        char dest[100];
        memset(dest, 'C', 100 - 1);
        dest[100 - 1] = '\0'; /* null terminate */
        destLen = strlen(dest);
        /* POTENTIAL FLAW: using length of the dest where data
         * could be smaller than dest causing buffer overread */
        for (i = 0; i < destLen; i++)
        {
            dest[i] = data[i];
        }
        dest[100 - 1] = '\0';
        printLine(dest);
    }
}

int main(int argc, char* argv[])
{
    //TODO: Add more examples
    /* seed randomness */
    srand((unsigned)time(NULL));
    CWE190_Integer_Overflow__char_fscanf_add_01_bad();
    CWE126_Buffer_Overread__char_alloca_loop_01_bad();
}