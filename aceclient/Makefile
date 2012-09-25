BIN=client
FILES=../aceserver/basemodule ../aceserver/datapacket ../aceserver/mycomutil ../aceserver/baseapp ../aceserver/aes clientmodule client
SRC=$(addsuffix .cpp,$(FILES))
OBJ=$(addsuffix .o,$(FILES))
BUILD=$(VBIN)
LIBS=-lACE -lbz2 -lsqlite3 -luuid
CPPFLAGS=-I../aceserver
VLDLIBS=$(LDLIBS:%=%$(VAR))
debug=1
optimize=0
threads=1
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
