# +++ csound~ makefile +++++++++++++++++++++++++++++++++++++++++++++++++++++

# pd source directory:
PD_SRC		= /home/steve/src/pd-0.34-2

# pd installation directory:
PD_LIB		= /usr/local/lib/pd

# misc programs + flags:
CC		= gcc
LD		= ld
DEBUG		= # -g -DDEBUG
INCLUDE		= -I$(PD_SRC)
SHARED		= -export_dynamic -shared
LDFLAGS		= $(SHARED) -lm
CFLAGS		+= -DPD -O2 -funroll-loops -fomit-frame-pointer \
		   -Wall -W -Wshadow -Wstrict-prototypes -Werror \
		   -Wno-unused -Wno-parentheses -Wno-switch \
		   $(INCLUDE) $(DEBUG)

# +++ few to edit below ++++++++++++++++++++++++++++++++++++++++++++++++++++

TARGET		= csound~

all: $(TARGET).pd_linux

.SUFFIXES: .pd_linux

.c.pd_linux:
	$(CC) $(CFLAGS) -o $*.o -c $*.c
	$(LD) $(LDFLAGS) -o $*.pd_linux $*.o
	strip --strip-unneeded $*.pd_linux

install: installdocs
	install -m 644 $(TARGET).pd_linux $(PD_LIB)/externs

installdocs:
	install -m 644 ../help/$(TARGET)* $(PD_LIB)/doc/5.reference

clean: ; rm -f *.pd_linux *.o

# +++ EOF ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
