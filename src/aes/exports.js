// shared asm.js module and heap
import {AES_asm} from './aes.asm';

export var _AES_heap_instance = new Uint8Array(0x100000);
export var _AES_asm_instance  = AES_asm( null, _AES_heap_instance.buffer );
