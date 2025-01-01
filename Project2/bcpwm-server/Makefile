TARGET = bcpwm-server
LIBS = -lm -lsodium -lssl -lcrypto -ldl
CC = g++
CFLAGS = -g

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
HEADERS = $(wildcard *.h)

%.o: %.cpp $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@ -DCROW_ENABLE_SSL

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LIBS) -o $@ -DCROW_ENABLE_SSL

clean:
	-rm -f *.o
	-rm -f $(TARGET)
