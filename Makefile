LDLIBS=-lpcap
CXXFLAGS += -g

all: tcp-block

tcp_block.o: mac.h ip.h ethhdr.h iphdr.h tcphdr.h tcp_block.c

tcphdr.o: tcphdr.h tcphdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

tcp-block: tcp_block.o tcphdr.o iphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o