import { sha256_asm, sha256result } from './sha256.asm';
import { Hash } from '../hash';
import { _heap_init } from '../../other/utils';

export const _sha256_block_size = 64;
export const _sha256_hash_size = 32;

export class Sha256 extends Hash<sha256result> {
  static NAME = 'sha256';
  public NAME = 'sha256';
  public BLOCK_SIZE = _sha256_block_size;
  public HASH_SIZE = _sha256_hash_size;

  constructor() {
    super();

    this.heap = _heap_init();
    this.asm = sha256_asm({ Uint8Array: Uint8Array }, null, this.heap.buffer);

    this.reset();
  }
}
