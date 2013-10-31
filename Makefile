
JS_FILES = js/*.js

all: asmcrypto.js

.PHONY: clean
clean:
	rm -f asmcrypto.js asmcrypto.js.map

asmcrypto.js: $(JS_FILES)
	uglifyjs $(JS_FILES) -c -m --wrap asmCrypto -o $@ --source-map $@.map
