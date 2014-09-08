// shared asm.js module and heap
var _aes_heap = new Uint8Array(0x100000),
    _aes_asm  = aes_asm( global, null, _aes_heap.buffer );
