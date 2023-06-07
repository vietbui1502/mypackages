# Global target; when 'make' is run without arguments, this is what it should do
PROGNAME = vcs-device-manager
VERSION = 1.0

CC=gcc
#CC = mipsel-openwrt-linux-musl-gcc

USE_CFLAGS = -g -ggdb -Wall -Wno-format -funsigned-char

# This variable holds all object file names, constructed from the source file names using pattern substitution
OBJFILES = monitor-client.c mongoose.c

all: $(PROGNAME)

$(PROGNAME):
	$(CC) $(USE_CFLAGS) $(OBJFILES) -o $(PROGNAME)

# To clean build artifacts, we specify a 'clean' rule, and use PHONY to indicate that this rule never matches with a potential file in the directory
.PHONY: clean
 
clean:
	rm -f $(PROGNAME) *.o

