import { IllegalArgumentError, IllegalStateError } from '../other/errors';
import { Hash } from '../hash/hash';
import { sha1result } from '../hash/sha1/sha1.asm';
import { sha256result } from '../hash/sha256/sha256.asm';
import { sha512result } from '../hash/sha512/sha512.asm';

export abstract class Hmac<T extends Hash<sha1result> | Hash<sha256result> | Hash<sha512result>> {
  public hash: T;
  protected BLOCK_SIZE: number;
  public HMAC_SIZE: number;
  protected key: Uint8Array;
  protected verify!: Uint8Array | null;
  public result!: Uint8Array | null;

  protected constructor(hash: T, password: Uint8Array, verify?: Uint8Array) {
    if (!hash.HASH_SIZE) throw new SyntaxError("option 'hash' supplied doesn't seem to be a valid hash function");

    this.hash = hash;
    this.BLOCK_SIZE = this.hash.BLOCK_SIZE;
    this.HMAC_SIZE = this.hash.HASH_SIZE;

    this.result = null;

    this.key = _hmac_key(this.hash, password);

    const ipad = new Uint8Array(this.key);
    for (let i = 0; i < ipad.length; ++i) ipad[i] ^= 0x36;

    this.hash.reset().process(ipad);

    if (verify !== undefined) {
      this._hmac_init_verify(verify);
    } else {
      this.verify = null;
    }
  }

  process(data: Uint8Array): this {
    if (this.result !== null) throw new IllegalStateError('state must be reset before processing new data');

    this.hash.process(data);

    return this;
  }

  finish(): this {
    if (this.result !== null) throw new IllegalStateError('state must be reset before processing new data');

    const inner_result = this.hash.finish().result as Uint8Array;

    const opad = new Uint8Array(this.key);
    for (let i = 0; i < opad.length; ++i) opad[i] ^= 0x5c;

    const verify = this.verify;
    const result = this.hash
      .reset()
      .process(opad)
      .process(inner_result)
      .finish().result as Uint8Array;

    if (verify) {
      if (verify.length === result.length) {
        let diff = 0;
        for (let i = 0; i < verify.length; i++) {
          diff |= verify[i] ^ result[i];
        }
        if (diff !== 0) throw new Error("HMAC verification failed, hash value doesn't match");
      } else {
        throw new Error("HMAC verification failed, lengths doesn't match");
      }
    }

    this.result = result;

    return this;
  }

  _hmac_init_verify(verify: Uint8Array): void {
    if (verify.length !== this.HMAC_SIZE) throw new IllegalArgumentError('illegal verification tag size');

    this.verify = verify;
  }
}

export function _hmac_key(hash: Hash<sha1result | sha256result | sha512result>, password: Uint8Array): Uint8Array {
  const key = new Uint8Array(hash.BLOCK_SIZE);

  if (password.length > hash.BLOCK_SIZE) {
    key.set(hash
      .reset()
      .process(password)
      .finish().result as Uint8Array);
  } else {
    key.set(password);
  }

  return key;
}
