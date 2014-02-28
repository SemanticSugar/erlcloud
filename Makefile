REBAR=./rebar

test: eunit

clean:
	@$(REBAR) clean

dialyzer:
	@$(REBAR) dialyze

all: compile

deps:
	@$(REBAR) get-deps

compile: deps
	@$(REBAR) compile

eunit: compile
	@rm -rf .eunit
	@mkdir -p .eunit
ifdef SUITE
	$(REBAR) skip_deps=true suites=$(SUITE) eunit
else
	$(REBAR) skip_deps=true eunit
endif
