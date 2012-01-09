BIN=client
FILES=../aceserver/basemodule ../aceserver/datapacket ../aceserver/mycomutil ../aceserver/baseapp clientmodule client
SRC=$(addsuffix .cpp,$(FILES))
OBJ=$(addsuffix .o,$(FILES))
BUILD=$(VBIN)
LIBS=-lACE
CPPFLAGS=-O0 -g -I../aceserver
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
