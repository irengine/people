core_target=pam_pgsql.so
HEADER=$(OBJ:%.o=%.h)

all_target: $(core_target)

SRC=\
	pam_get_pass.c  \
	pam_get_service.c \
	backend_pgsql.c \
	pam_pgsql_options.c \
	pam_pgsql.c

OBJ=\
	pam_get_pass.o  \
	pam_get_service.o \
	backend_pgsql.o \
	pam_pgsql_options.o \
	pam_pgsql.o 

CC=g++

CPPFLAGS=-g -I/usr/pgsql-9.1/include -fPIC
LDFLAGS=-L/usr/pgsql-9.1/lib -lpam -lpq -lgcrypt -shared

pam_pgsql.so : $(OBJ)
	g++ $(CFLAGS) $(OBJ) $(LDFLAGS) -o pam_pgsql.so
	
clean:
	rm -f *.o *~ pam_pgsql.so core

depend:
	makedepend -- $(CFLAGS) -- $(SRC)

# DO NOT DELETE

