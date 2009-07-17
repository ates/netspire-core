CC=gcc
CFLAGS=-Wall
LDFLAGS=-lssl
LIB_DIR=../priv/lib
INCLUDE=-I/usr/lib/erlang/usr/include

compile: $(LIB_DIR) netspire_crypto_drv.so

$(LIB_DIR):
	test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)

netspire_crypto_drv.so: netspire_crypto_drv.c
	$(CC) $(INCLUDE) $(CFLAGS) $(LDFLAGS) -fpic -shared -o $(LIB_DIR)/netspire_crypto_drv.so netspire_crypto_drv.c

clean:
	rm -rf $(LIB_DIR)/*.so
