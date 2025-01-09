CXXFLAGS = -Wall -g
#CXXFLAGS = -Wall -O3

all:
	g++ $(CXXFLAGS) main.cpp -o main
	g++ $(CXXFLAGS) -c -S main.cpp

clean:
	rm -f main
	rm -f main.s
	rm -f *.o
