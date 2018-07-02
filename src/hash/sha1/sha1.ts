import { sha1_asm, sha1result } from './sha1.asm';
import { Hash } from '../hash';

export const _sha1_block_size = 64;
export const _sha1_hash_size = 20;

export class Sha1 extends Hash<sha1result> {
  static NAME = 'sha1';
  public NAME = 'sha1';
  public BLOCK_SIZE = _sha1_block_size;
  public HASH_SIZE = _sha1_hash_size;

  protected static heap_pool = [];
  protected static asm_pool = [];
  protected static asm_function = sha1_asm;

  static bytes(data: Uint8Array): Uint8Array {
    return new Sha1().process(data).finish().result;
  }
}
