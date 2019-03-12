msh: libFAT32.so
	gcc -Wall -fPIC -I. -o msh newTest.c -L. -lFAT32

libFAT32.so: 
	gcc -std=c99 -shared -o libFAT32.so -fPIC Fat32Lib.c

clean: 
	rm *.so msh
