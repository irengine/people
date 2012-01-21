BIN=server
FILES=basemodule distmodule baseapp datapacket mycomutil middlemodule server md5 dbmodule aes
SRC=$(addsuffix .cpp,$(FILES))
OBJ=$(addsuffix .o,$(FILES))
BUILD=$(VBIN)
LIBS=-L/usr/pgsql-9.1/lib -lACE -lbz2 -lpq
CPPFLAGS=-O0 -g -I/usr/pgsql-9.1/include
VLDLIBS=$(LDLIBS:%=%$(VAR))
#---------------------------------------------------------
# Include macros and targets
#---------------------------------------------------------
include $(ACE_ROOT)/include/makeinclude/wrapper_macros.GNU
include $(ACE_ROOT)/include/makeinclude/macros.GNU
include $(ACE_ROOT)/include/makeinclude/rules.common.GNU
include $(ACE_ROOT)/include/makeinclude/rules.nonested.GNU
include $(ACE_ROOT)/include/makeinclude/rules.bin.GNU
include $(ACE_ROOT)/include/makeinclude/rules.local.GNU
