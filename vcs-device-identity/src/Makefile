# Global target; when 'make' is run without arguments, this is what it should do
PROGNAME = vcs-device-identity
VERSION = 1.0

#CC=gcc
CC = mipsel-openwrt-linux-musl-gcc

BASIC_CFLAGS = -Wall -Wno-format -I/home/vietbv/github/openwrt/staging_dir/target-mipsel_24kc_musl/usr/include -DVERSION=\"$(VERSION)\" $(CFLAGS)

# BASIC_CFLAGS = -Wall -Wno-format -I/usr/local/include/ -I/opt/local/include/ -DVERSION=\"$(VERSION)\" $(CFLAGS)

BASIC_LDFLAGS = -L/home/vietbv/github/openwrt/staging_dir/target-mipsel_24kc_musl/usr/lib $(LDFLAGS)
#BASIC_LDFLAGS = -L/usr/local/lib/ -L/opt/local/lib $(LDFLAGS)

USE_CFLAGS = -fstack-protector-all -fPIE -D_FORTIFY_SOURCE=2 -g -ggdb $(BASIC_CFLAGS)

USE_LDFLAGS =-Wl,-z,relro -pie $(BASIC_LDFLAGS)

USE_LIBS = -lpcap -lpthread $(LIBS)

# This variable holds all object file names, constructed from the source file names using pattern substitution
OBJFILES = api.c process.c fp_tcp.c fp_mtu.c fp_http.c readfp.c device.c

#BASIC_CFLAGS=$(BASIC_CFLAGS) -O3
#USE_CFLAGS=$(USE_CFLAGS) -O3

all: $(PROGNAME)

$(PROGNAME):
	$(CC) $(USE_CFLAGS) $(USE_LDFLAGS) p0f.c $(OBJFILES) -o $(PROGNAME) $(USE_LIBS)

# To clean build artifacts, we specify a 'clean' rule, and use PHONY to indicate that this rule never matches with a potential file in the directory
.PHONY: clean
 
clean:
	rm -f $(PROGNAME) *.o

