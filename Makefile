ERL=erl
APP_NAME=netspire
MNESIA_FLAGS=-mnesia dir \"/tmp/netspire\"
CONFIG_FLAGS=-netspire config \"netspire.conf\"
SNODE_NAME=netspire
EFLAGS=+W w -pa ebin $(CONFIG_FLAGS) $(MNESIA_FLAGS) -sname $(SNODE_NAME)
VSN=$(shell awk -F\" '/vsn/ { print $$2 }\' netspire.app)

all: compile

compile:
	test -d ebin || mkdir ebin
	$(ERL) $(EFLAGS) -make
	cp $(APP_NAME).app ebin

doc:
	$(ERL) -noshell -run edoc_run application "'$(APP_NAME)'" '"."' \
		'[{def, {vsn, "$(VSN)"}}, {packages, false}]'

clean:
	test ! -d doc || rm -rf doc
	rm -rf ebin erl_crash.dump
	find . -name "*~" -delete

run: compile
	$(ERL) $(EFLAGS) -eval 'application:start($(APP_NAME)).'

console: compile
	$(ERL) $(EFLAGS)
