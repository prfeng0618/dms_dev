DMS_DEV = dms_dev

CC = /opt/buildroot-gcc463/usr/bin/mipsel-buildroot-linux-uclibc-gcc
#CC = gcc
LDFLAGS = -I.
LIBS = -L/opt/buildroot-gcc463/usr/mipsel-buildroot-linux-uclibc/sysroot/lib/
LIBEX = -lpthread
CFLAGS = -g -rdynamic
CCOMPILE = $(CC) $(LDFLAGS) $(CFLAGS) -c  

CXX = /opt/buildroot-gcc463/usr/bin/mipsel-buildroot-linux-uclibc-g++
#CXX = g++
CPPFLAGS =
CXXCOMPILE = $(CXX) $(CPPFLAGS) $(CFLAGS) -c  
#LDFLAGS = -lrt -lz  
#CFLAGS = -Wall -ggdb3  

STRIP = /opt/buildroot-gcc463/usr/bin/mipsel-buildroot-linux-uclibc-strip
#STRIP = strip
LINKCC = $(CXX) $(LDFLAGS)  
#LIBA = libcshm.a  
LIBA = 

#CSRCS := $(wildcard *.c)     
CSRCS := dms_dev.c debug.c cJSON.c thread.c dms_manage_wifi.c 
COBJS := $(patsubst %.c,%.o,$(CSRCS))  
#CXXSRCS := $(wildcard *.cpp)  
CXXSRCS := dms_zigbee.cpp
CXXOBJS := $(patsubst %.cpp,%.o,$(CXXSRCS))

all:$(DMS_DEV)
	$(STRIP) $(DMS_DEV)
 
$(DMS_DEV): $(COBJS) $(CXXOBJS)  
	$(LINKCC) $(COBJS) $(CXXOBJS) $(LIBA) -o $@ $(LIBS) $(LIBEX)	

$(COBJS):
	$(CCOMPILE) $< $(CSRCS)
	
$(CXXOBJS):
	$(CXXCOMPILE) $< $(CXXSRCS)
		
	
#%.d:%.c  
#    $(CC) -MM $(CPPFLAGS) $< > $@  
#%.o:%.c  
#    $(COMPILE) $< -o $@  
	
.PHONY: clean backup git
clean: 
	rm -f $(COBJS) $(CXXOBJS) $(DMS_DEV)  

HFILE := cJSON.h debug.h dms_dev.h dms_zigbee.h InnerClient.h list.h utils.h wireless.h
backup:
	rm backup -rf
	mkdir backup
	cp $(CSRCS) $(CXXSRCS) $(HFILE) Makefile backup
git:
	git add $(CSRCS) $(CXXSRCS) $(HFILE) Makefile

explain:  
	@echo "The information represents in the program:"  
	@echo "Final executable name: $(DMS_DEV)"  
	@echo "Source files: $(CSRCS) $(CXXSRCS)"  
	@echo "Object files: $(COBJS) $(CXXOBJS)"  
#depend:$(DEPS)  
#    @echo "Dependencies are now up-to-date"  
#-include $(DEPS)  
