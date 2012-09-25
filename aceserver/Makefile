BIN=sapp
FILES=component distmodule app datapacket tools middlemodule sapp sall dbmodule 
SRC=$(addsuffix .cpp,$(FILES))
OBJ=$(addsuffix .o,$(FILES))
BUILD=$(VBIN)
LIBS=-L/usr/pgsql-9.1/lib -lACE -lbz2 -lpq -luuid
CPPFLAGS=-I/usr/pgsql-9.1/include -std=c++0x
VLDLIBS=$(LDLIBS:%=%$(VAR))
debug=1
optimize=0
#---------------------------------------------------------
# Include macros and targets
#---------------------------------------------------------
include $(ACE_ROOT)/include/makeinclude/wrapper_macros.GNU
include $(ACE_ROOT)/include/makeinclude/macros.GNU
include $(ACE_ROOT)/include/makeinclude/rules.common.GNU
include $(ACE_ROOT)/include/makeinclude/rules.nonested.GNU
include $(ACE_ROOT)/include/makeinclude/rules.bin.GNU
include $(ACE_ROOT)/include/makeinclude/rules.lib.GNU
include $(ACE_ROOT)/include/makeinclude/rules.local.GNU
