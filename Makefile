objs = utils.o 

hdrs = utils.h

srcs = utils.c
LIBUTILS := libutils.so
CFLAGS += -std=gnu99

FPIC = -fPIC -Wall -Wextra -O2 -g
SHARED = -shared
GDB := -g

all: $(LIBUTILS)

$(LIBUTILS): $(objs)
	$(CC) $(LDFLAGS) $(FPIC) $(SHARED) $(LIBS) $(objs)  -o $(LIBUTILS)


utils.o: $(srcs) $(hdrs)
	$(CC) $(CFLAGS) $(FPIC) $(GDB) -c $(srcs) -o $(objs)

# remove object files and executable when user executes "make clean"
.PHONY : clean
clean :
	rm $(objs)