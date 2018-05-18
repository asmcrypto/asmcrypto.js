import { sha1_asm, sha1result } from './sha1.asm';
import { Hash } from '../hash';
import { _heap_init } from '../../other/utils';

export const _sha1_block_size = 64;
export const _sha1_hash_size = 20;

export class Sha1 extends Hash<sha1result> {
  static NAME = 'sha1';
  public NAME = 'sha1';
  public BLOCK_SIZE = _sha1_block_size;
  public HASH_SIZE = _sha1_hash_size;

  constructor() {
    super();

    this.heap = _heap_init();
    this.asm = sha1_asm({ Uint8Array: Uint8Array }, null, this.heap.buffer);

    this.reset();
  }
}
