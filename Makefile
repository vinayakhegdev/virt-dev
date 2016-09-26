obj-m += nv_fs.o
nv_fs-objs := nv_drv.o nv_mem.o nv_vd.o nv_block.o nv_device.o 
KDIR := /lib/modules/4.0.0+/build
PWD := $(shell pwd)

ccflags-y := -D_LARGEFILE64_SOURCE
CC := $(CROSS_COMPILE)gcc

all:
	$(MAKE) -C $(KDIR) M=${shell pwd} modules
        
clean:
	-$(MAKE) -C $(KDIR) M=${shell pwd} clean || true
