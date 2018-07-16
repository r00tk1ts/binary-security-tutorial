/*
* This program is used to demonstrate classical stack-based overflow procedure.
* In Linux platform, you should compile as below with gcc:
*		echo 0 > /proc/sys/kernel/randomize_va_space
*		gcc -Wall -g -fno-stack-protector  -o stack_overflow stack_overflow.c -m32 -Wl,-zexecstack
* In Windows platform (In most case, VS), you can manually modify the project
* properties to deploy the same configuration.
*/
#include <stdio.h>
#include <stdlib.h>

unsigned char opcode[] = "\x5f\x5e\xc3";

void vul_func()
{
	char buf[64] = { 0 };
	FILE *fp = NULL;
	
	if (!(fp = fopen("input.txt", "r")))
	{
		perror("fopen");
		exit(-1);
	}
	fread(buf, 1024, 1, fp);
	printf("data:%s\n", buf);
}

int main(int argc, char *argv[])
{
	vul_func();
	return 0;
}
