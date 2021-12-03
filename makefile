LDLIBS=-lpcap

all: airodump

airodump: mac.o main.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o