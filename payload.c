/*
 * gcc test.c -nostdlib -fpic -pie -o test
 * */

/*void quit(long int exitCode){
	asm volatile(
		"mov $60, %%rax\n\t"
		"mov %0, %%rdi\n\t"
		"syscall\n\t" : : "g"(exitCode)
	);	
}*/

void _start(void){
	// example of program diversion
	// Actual Program 
	asm volatile(
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
	);
	char msg[18] = {'I', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'M', 'a', 't', 'e', 'r', '\n', '\0'};
	asm volatile(
                "mov %0, %%rsi\n\t"
		"mov $1, %%rax\n\t"
                "mov $1, %%rdi\n\t"
                "mov $18, %%rdx\n\t"
                "syscall\n" : :"g"(msg)
        );

//	return 1;
}
