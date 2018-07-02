import { sha256_asm, sha256result } from './sha256.asm';
import { Hash } from '../hash';

export const _sha256_block_size = 64;
export const _sha256_hash_size = 32;

export class Sha256 extends Hash<sha256result> {
  static NAME = 'sha256';
  public NAME = 'sha256';
  public BLOCK_SIZE = _sha256_block_size;
  public HASH_SIZE = _sha256_hash_size;

  protected static heap_pool = [];
  protected static asm_pool = [];
  protected static asm_function = sha256_asm;

  static bytes(data: Uint8Array): Uint8Array {
    return new Sha256().process(data).finish().result;
  }
}
