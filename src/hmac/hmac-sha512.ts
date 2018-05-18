import { Hmac } from './hmac';
import { IllegalStateError } from '../other/errors';
import { _sha512_hash_size, Sha512 } from '../hash/sha512/sha512';
import { Hash } from '../hash/hash';
import { sha512result } from '../hash/sha512/sha512.asm';

export class HmacSha512 extends Hmac<Hash<sha512result>> {
  public result!: Uint8Array | null;

  constructor(password: Uint8Array, verify?: Uint8Array) {
    const hash = new Sha512();

    // Calculate ipad, init the underlying engine, calculate this.key
    super(hash, password, verify);

    this.reset();

    if (verify !== undefined) {
      this._hmac_init_verify(verify);
    } else {
      this.verify = null;
    }

    return this;
  }

  reset(): this {
    const key = this.key;
    this.hash
      .reset()
      .asm.hmac_init(
        (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3],
        (key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7],
        (key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11],
        (key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15],
        (key[16] << 24) | (key[17] << 16) | (key[18] << 8) | key[19],
        (key[20] << 24) | (key[21] << 16) | (key[22] << 8) | key[23],
        (key[24] << 24) | (key[25] << 16) | (key[26] << 8) | key[27],
        (key[28] << 24) | (key[29] << 16) | (key[30] << 8) | key[31],
        (key[32] << 24) | (key[33] << 16) | (key[34] << 8) | key[35],
        (key[36] << 24) | (key[37] << 16) | (key[38] << 8) | key[39],
        (key[40] << 24) | (key[41] << 16) | (key[42] << 8) | key[43],
        (key[44] << 24) | (key[45] << 16) | (key[46] << 8) | key[47],
        (key[48] << 24) | (key[49] << 16) | (key[50] << 8) | key[51],
        (key[52] << 24) | (key[53] << 16) | (key[54] << 8) | key[55],
        (key[56] << 24) | (key[57] << 16) | (key[58] << 8) | key[59],
        (key[60] << 24) | (key[61] << 16) | (key[62] << 8) | key[63],
        (key[64] << 24) | (key[65] << 16) | (key[66] << 8) | key[67],
        (key[68] << 24) | (key[69] << 16) | (key[70] << 8) | key[71],
        (key[72] << 24) | (key[73] << 16) | (key[74] << 8) | key[75],
        (key[76] << 24) | (key[77] << 16) | (key[78] << 8) | key[79],
        (key[80] << 24) | (key[81] << 16) | (key[82] << 8) | key[83],
        (key[84] << 24) | (key[85] << 16) | (key[86] << 8) | key[87],
        (key[88] << 24) | (key[89] << 16) | (key[90] << 8) | key[91],
        (key[92] << 24) | (key[93] << 16) | (key[94] << 8) | key[95],
        (key[96] << 24) | (key[97] << 16) | (key[98] << 8) | key[99],
        (key[100] << 24) | (key[101] << 16) | (key[102] << 8) | key[103],
        (key[104] << 24) | (key[105] << 16) | (key[106] << 8) | key[107],
        (key[108] << 24) | (key[109] << 16) | (key[110] << 8) | key[111],
        (key[112] << 24) | (key[113] << 16) | (key[114] << 8) | key[115],
        (key[116] << 24) | (key[117] << 16) | (key[118] << 8) | key[119],
        (key[120] << 24) | (key[121] << 16) | (key[122] << 8) | key[123],
        (key[124] << 24) | (key[125] << 16) | (key[126] << 8) | key[127],
      );
    return this;
  }

  finish() {
    if (this.key === null) throw new IllegalStateError('no key is associated with the instance');

    if (this.result !== null) throw new IllegalStateError('state must be reset before processing new data');

    const hash = this.hash;
    const asm = this.hash.asm;
    const heap = this.hash.heap;

    asm.hmac_finish(hash.pos, hash.len, 0);

    const verify = this.verify;
    const result = new Uint8Array(_sha512_hash_size);
    result.set(heap.subarray(0, _sha512_hash_size));

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
    } else {
      this.result = result;
    }

    return this;
  }
}
