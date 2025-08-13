CC      = cc
CFLAGS  = -O2 -Wall -Wextra -std=c2x -D_POSIX_C_SOURCE=200809L
TARGET  = ping
OBJS    = ping.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lm

ping.o: ping.c ping.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

