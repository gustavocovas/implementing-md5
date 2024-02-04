CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lm

TARGET = md5

all: $(TARGET) 

$(TARGET): md5.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
