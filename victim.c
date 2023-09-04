#include <stdio.h>
#include <stdlib.h>

int mathEquation(int a, int b){
	return a*b+3;
}
int main(int argc, char *argv[]){
	printf("You've run the %s program!\n", argv[0]);
	int a = mathEquation(5, 8);
	printf("Result : %d\n", a);
	return 0;
}
