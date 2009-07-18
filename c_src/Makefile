CC=gcc
OBJ_DIR=../priv/obj
LIB_DIR=../priv/lib

TARGET=$(shell uname)

ifeq ($(TARGET), Darwin)
CFLAGS=-c -Wall -O2 -no-cpp-precomp -DUSE_THREADS -D_THREAD_SAFE -D_REENTRANT -fPIC -fno-common
LDFLAGS=-L/usr/lib -lcrypto -bundle -flat_namespace -undefined suppress
INCLUDE=-I/opt/local/lib/erlang/usr/include
else
CFLAGS=-Wall -fpic -shared
LDFLAGS=-lcrypto
INCLUDE=-I/usr/lib/erlang/usr/include
endif

compile: $(LIB_DIR) \
	netspire_crypto_drv.so

$(LIB_DIR):
	test -d $(OBJ_DIR) || mkdir -p $(OBJ_DIR)
	test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)

netspire_crypto_drv.so: netspire_crypto_drv.c
ifeq ($(TARGET), Darwin)
	$(CC) $(INCLUDE) $(CFLAGS) -o ../priv/obj/netspire_crypto_drv.o netspire_crypto_drv.c
	$(CC) $(LDFLAGS) -o ../priv/lib/netspire_crypto_drv.so ../priv/obj/netspire_crypto_drv.o
else
	$(CC) $(INCLUDE) $(LDFLAGS) $(CFLAGS) -o $(LIB_DIR)/netspire_crypto_drv.so netspire_crypto_drv.c
endif

clean:
	rm -rf $(OBJ_DIR)/*.o
	rm -rf $(LIB_DIR)/*.so
