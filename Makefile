APP_NAME=netspire
MNESIA_FLAGS = -mnesia dir \"/tmp/netspire\"
CONFIG_FLAGS = -netspire config \"netspire.conf\"
SNODE_NAME = netspire
EFLAGS = +W w -pa ebin $(CONFIG_FLAGS) $(MNESIA_FLAGS) -sname $(SNODE_NAME)

ifeq ($(shell which rlwrap 2> /dev/null),)
		ERL=erl
else
		ERL=rlwrap erl -oldshell
endif

all: compile

compile:
		make -C c_src compile
		test -d ebin || mkdir ebin
		$(ERL) $(EFLAGS) -make
		cp $(APP_NAME).app ebin

clean:
		make -C c_src clean
		rm -rf ebin erl_crash.dump
		find . -name "*~" -delete

run: compile
		$(ERL) $(EFLAGS) -eval 'application:start($(APP_NAME)).'

console: compile
		$(ERL) $(EFLAGS)
