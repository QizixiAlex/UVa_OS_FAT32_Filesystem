CXX=g++
CXXFLAGS=-Wall -pedantic -std=c++11

all: myfat

myfat: myfat.o
	$(CXX) $(CXXFLAGS) -o $@ $^

myfat.o: myfat.cc myfat.h

clean:
	rm -f *.o myfat

debug: myfat.cc myfat.h
	$(CXX) $(CXXFLAGS) -g $@ $^

