obj-m := simple_kernel_module.o

SRC := $(shell pwd)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(SRC) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(SRC) clean
