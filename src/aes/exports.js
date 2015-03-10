// shared asm.js module and heap
var _AES_heap_instance = new Uint8Array(0x100000),
    _AES_asm_instance  = AES_asm( global, null, _AES_heap_instance.buffer );
