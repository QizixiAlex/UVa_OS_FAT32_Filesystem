msh: libFAT32.so
	g++ -Wall -fPIC -I. -o msh newTest.c -L. -lFAT32

libFAT32.so: 
	g++ -std=c++11 -shared -o libFAT32.so -fPIC myfat.cc

clean: 
	rm *.so msh
