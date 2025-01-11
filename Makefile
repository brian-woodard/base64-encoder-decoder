CXXFLAGS = -Wall -g
#CXXFLAGS = -Wall -O3

all:
	g++ $(CXXFLAGS) -c PrintData.cpp
	g++ $(CXXFLAGS) main.cpp -o main PrintData.o
	g++ $(CXXFLAGS) sha1.cpp -o sha1 PrintData.o
	g++ $(CXXFLAGS) websocket_server.cpp -o websocket_server PrintData.o
#	g++ $(CXXFLAGS) -c -S main.cpp

clean:
	rm -f main
	rm -f sha1
	rm -f main.s
	rm -f *.o
