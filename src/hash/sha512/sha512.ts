import { sha512_asm, sha512result } from './sha512.asm';
import { Hash } from '../hash';

export const _sha512_block_size = 128;
export const _sha512_hash_size = 64;

export class Sha512 extends Hash<sha512result> {
  static NAME = 'sha512';
  public NAME = 'sha512';
  public BLOCK_SIZE = _sha512_block_size;
  public HASH_SIZE = _sha512_hash_size;

  protected static heap_pool = [];
  protected static asm_pool = [];
  protected static asm_function = sha512_asm;
}
