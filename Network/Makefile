all: main

sum: main.o sum.o
	gcc -o sum sum.o main.c

sum.o: sum.h sum.c
	gcc -c -o sum.o sum.c

main.o: sum.h main.c
	gcc -c -o main.o main.c

clean:
	rm -f *.o sum


