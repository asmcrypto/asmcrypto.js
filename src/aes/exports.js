// shared asm.js module and heap
var _aes_heap_instance = new Uint8Array(0x100000),
    _aes_asm_instance  = aes_asm( global, null, _aes_heap_instance.buffer );

function createSimpleCipherInterface ( Constructor )
{
    return function SimpleCipher ( options ) {
        var _instance = new Constructor(options);

        Object.defineProperties( this, {
            mode: {
                value: _instance.mode
            },
            encrypt: {
                value: function ( data, options ) {
                    if ( options && options.key !== undefined ) throw new IllegalStateError("'key' option is forbidden on cipher instance");
                    return _instance.reset(options).encrypt(data).result;
                }
            },
            decrypt: {
                value: function ( data, options ) {
                    if ( options && options.key !== undefined ) throw new IllegalStateError("'key' option is forbidden on cipher instance");
                    return _instance.reset(options).decrypt(data).result;
                }
            }
        });
    };
}

function createProgressiveCipherInterface ( Constructor )
{
    return function ProgressiveCipher ( options ) {
        var _instance = new Constructor(options);

        if ( _instance.hasOwnProperty('padding') ) {
            Object.defineProperty( this, 'padding', {
                value: _instance.padding
            });
        }

        if ( _instance.hasOwnProperty('iv') ) {
            Object.defineProperty( this, 'iv', {
                value: _instance.iv
            });
        }

        Object.defineProperties( this, {
            mode: {
                value: _instance.mode
            },
            process: {
                value: function ( data ) {
                    return _instance.process(data).result;
                }
            },
            finish: {
                value: function ( data ) {
                    return _instance.finish(data).result;
                }
            }
        });
    };
}
