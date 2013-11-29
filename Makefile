
JS_FILES = js/helpers.js \
           js/aes.asm.js js/aes.js \
           js/sha256.asm.js js/sha256.js \
           js/hmac.js \
           js/pbkdf2.js

all: asmcrypto.js

.PHONY: clean
clean:
	rm -f asmcrypto.js asmcrypto.js.map

asmcrypto.js: $(JS_FILES)
	uglifyjs $(JS_FILES) -b --wrap asmCrypto -o $@ --source-map $@.map
