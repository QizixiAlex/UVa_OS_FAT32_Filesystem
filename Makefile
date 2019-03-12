CXX=g++
CXXFLAGS=-Wall -Werror -pedantic -std=c++11

all: myfat

myfat: myfat.o
	$(CXX) $(CXXFLAGS) -o $@ $^

myfat.o: myfat.cc myfat.h

clean:
	rm -f *.o myfat


