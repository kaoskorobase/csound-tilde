PD_SRC		= /home/steve/src/pd-0.34-2
PD_LIB		= /usr/local/lib/pd

CC		= gcc
LD		= ld
DEBUG		= # -g -DDEBUG
INCLUDE		= -I$(PD_SRC)
SHARED		= -export_dynamic -shared
LDFLAGS		= $(SHARED) -lm
CFLAGS		+= -DPD -O3 -funroll-loops -fomit-frame-pointer \
		   -Wall -W -Wshadow -Wstrict-prototypes -Werror \
		   -Wno-unused -Wno-parentheses -Wno-switch \
		   $(INCLUDE) $(DEBUG)

# -------------------- DO NOT EDIT BELOW --------------------

TARGET		= csound~.pd_linux

all: $(TARGET)

.SUFFIXES: .pd_linux

.c.pd_linux:
	$(CC) $(CFLAGS) -o $*.o -c $*.c
	$(LD) $(LDFLAGS) -o $*.pd_linux $*.o
	strip --strip-unneeded $*.pd_linux

install: installdocs
	install -m 644 $(TARGET).pd_linux $(PD_LIB)/externs

installdocs:
	install -d $(PD_LIB)/doc/5.reference/zexy
	install -m644 ../examples/* $(PD_DIR)/doc/5.reference/zexy

clean: rm -f *.pd_linux *.o

# EOF