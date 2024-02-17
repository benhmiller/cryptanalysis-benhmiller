#
# COMPSCI642 - F23 Project 1 - Cryptanalysis
# Makefile - makefile for the assignment
#

# Locations


# Make environment
ARCH:=$(shell uname -p)
INCLUDES=-I.
CC=./642cc-$(ARCH)
CFLAGS=-I. -c -g -Wall $(INCLUDES)
LINKARGS=-g
LIBS=-lcompsci642 -lm -lcrypto-$(ARCH) -lgcrypt -lpthread -lcurl

# Suffix rules
.SUFFIXES: .c .o

.c.o:
		$(CC) $(CFLAGS)  -o $@ $<

# Files
TARGET=cryptanalysis
OBJECT_FILES=	cs642-cryptanalysis.o \
				cs642-cryptanalysis-impl.o \

# Productions
all : $(TARGET)

$(TARGET) : $(OBJECT_FILES)
	$(CC) $(LINKARGS) $(OBJECT_FILES) -o $@ $(LIBS)

clean :
	rm -f $(TARGET) $(OBJECT_FILES)

test: $(TARGET)
	./$(TARGET) -v

debug: $(TARGET)
	gdb ./$(TARGET)

memdebug: $(TARGET)
	valgrind --leak-check=full ./$(TARGET) -v
