import { BigNumber, Modulus } from '../bignum/bignum';
import { IllegalStateError } from '../other/errors';

export type key = {
  0: Modulus;
  1: BigNumber;
  2?: BigNumber;
  3?: Modulus;
  4?: Modulus;
  5?: BigNumber;
  6?: BigNumber;
  7?: BigNumber;
};

export class RSA {
  public readonly key: key;
  public result!: Uint8Array;

  constructor(key: Uint8Array[]) {
    const l = key.length;
    if (l !== 2 && l !== 3 && l !== 8) throw new SyntaxError('unexpected key type');

    const k0 = new Modulus(new BigNumber(key[0]));
    const k1 = new BigNumber(key[1]);
    this.key = {
      0: k0,
      1: k1,
    };
    if (l > 2) {
      this.key[2] = new BigNumber(key[2]);
    }
    if (l > 3) {
      this.key[3] = new Modulus(new BigNumber(key[3]));
      this.key[4] = new Modulus(new BigNumber(key[4]));
      this.key[5] = new BigNumber(key[5]);
      this.key[6] = new BigNumber(key[6]);
      this.key[7] = new BigNumber(key[7]);
    }
  }

  encrypt(msg: BigNumber): this {
    if (!this.key) throw new IllegalStateError('no key is associated with the instance');

    if (this.key[0].compare(msg) <= 0) throw new RangeError('data too large');

    const m = this.key[0];
    const e = this.key[1];

    let result = m.power(msg, e).toBytes();

    const bytelen = (m.bitLength + 7) >> 3;
    if (result.length < bytelen) {
      const r = new Uint8Array(bytelen);
      r.set(result, bytelen - result.length);
      result = r;
    }

    this.result = result;

    return this;
  }

  decrypt(msg: BigNumber): this {
    if (this.key[0].compare(msg) <= 0) throw new RangeError('data too large');

    let result;
    let m;
    if (this.key[3] !== undefined) {
      m = this.key[0] as BigNumber;
      const p = this.key[3] as Modulus;
      const q = this.key[4] as Modulus;
      const dp = this.key[5] as BigNumber;
      const dq = this.key[6] as BigNumber;
      const u = this.key[7] as BigNumber;

      const x = p.power(msg, dp);
      const y = q.power(msg, dq);

      let t = x.subtract(y);
      while (t.sign < 0) t = t.add(p);

      const h = p.reduce(u.multiply(t));

      result = h
        .multiply(q)
        .add(y)
        .clamp(m.bitLength)
        .toBytes();
    } else {
      m = this.key[0];
      const d = this.key[2] as BigNumber;

      result = m.power(msg, d).toBytes();
    }

    const bytelen = (m.bitLength + 7) >> 3;
    if (result.length < bytelen) {
      let r = new Uint8Array(bytelen);
      r.set(result, bytelen - result.length);
      result = r;
    }

    this.result = result;

    return this;
  }
}
