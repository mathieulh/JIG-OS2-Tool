TARGET = decrypt_os2
OBJS = main.c 

INCDIR = include
CFLAGS = -O2 -G0 -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS) -c

LIBDIR =
LDFLAGS = lib/
LIBS = -lkirk 

all:
	gcc $(OBJS) -I$(INCDIR) -o $(TARGET) -L$(LDFLAGS) $(LIBS)