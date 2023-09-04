all:
	gcc eirus.c -o eirus
	gcc victim.c -o victim
	gcc payload.c -nostdlib -fpic -pie -o payload
main:
	gcc eirus.c -o eirus
victim:
	gcc victim.c -o victim
warhead:
	# -N can help with compiling without .rodata, but more research required.
	gcc payload.c -Wall -nostdlib -fpic -fpie -o payload
clean:
	rm eirus victim payload
