#include <windows.h>
#include <stdio.h>

#define DLL_NAME "user32.dll"

int main()
{
	BYTE *ptr;
	int position, address;
	HINSTANCE handle;
	BOOL done_flag = FALSE;
	handle = LoadLibrary(TEXT(DLL_NAME));
	if (!handle)
	{
		printf(" load dll error !");
		exit(0);
	}
	ptr = (BYTE*)handle;

	for (position = 0; !done_flag; position++)
	{
		try
		{
			if (ptr[position] == 0xFF && ptr[position + 1] == 0xE4)
			{
				// 0xFFE4 is the opcode of jmp esp
				int address = (int)ptr + position;
				printf("OPCODE found at 0x%x\n", address);
			}
		}
		catch (...)
		{
			int address = (int)ptr + position;
			printf("END OF 0x%x\n", address);
			done_flag = true;
		}
	}
}