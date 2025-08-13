CC      = cc
CFLAGS  = -O2 -Wall -Wextra -std=c2x
TARGET  = ping
OBJS    = ping.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

ping.o: ping.c ping.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

