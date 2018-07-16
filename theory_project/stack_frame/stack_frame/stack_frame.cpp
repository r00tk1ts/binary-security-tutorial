#include <stdio.h>

int func_B(int arg_B1, int arg_B2)
{
	int var_B1, var_B2;
	var_B1 = arg_B1 + arg_B2;
	var_B2 = arg_B1 - arg_B2;
	return var_B1 * var_B2;
}

int func_A(int arg_A1, int arg_A2)
{
	int var_A;
	var_A = func_B(arg_A1, arg_A2) + arg_A1;
	return var_A;
}

int main(int argc, char **argv, char **envp)
{
	int var_main;
	var_main = func_A(4, 3);
	printf("var_main:%d\n", var_main);
	return var_main;
}
