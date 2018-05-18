import { sha512_asm, sha512result } from './sha512.asm';
import { Hash } from '../hash';
import { _heap_init } from '../../other/utils';

export const _sha512_block_size = 128;
export const _sha512_hash_size = 64;

export class Sha512 extends Hash<sha512result> {
  static NAME = 'sha512';
  public NAME = 'sha512';
  public BLOCK_SIZE = _sha512_block_size;
  public HASH_SIZE = _sha512_hash_size;

  constructor() {
    super();

    this.heap = _heap_init();
    this.asm = sha512_asm({ Uint8Array: Uint8Array }, null, this.heap.buffer);

    this.reset();
  }
}
