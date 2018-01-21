import { Random_getValues } from '../random/random';
import { bigint_asm } from './bigint.asm';
import { is_buffer, is_bytes, is_number, is_string, string_to_bytes } from '../utils';
import { IllegalArgumentError } from '../errors';
import { BigNumber_extGCD, Number_extGCD } from './extgcd';

export function is_big_number(a) {
  return a instanceof BigNumber_constructor;
}

///////////////////////////////////////////////////////////////////////////////

export var _bigint_stdlib = { Uint32Array: Uint32Array, Math: Math };
export var _bigint_heap = new Uint32Array(0x100000);
export var _bigint_asm;

// Small primes for trail division
const _primes = [2, 3 /* and so on, computed lazily */];

function _half_imul(a, b) {
  return (a * b) | 0;
}

if (_bigint_stdlib.Math.imul === undefined) {
  _bigint_stdlib.Math.imul = _half_imul;
  _bigint_asm = bigint_asm(_bigint_stdlib, null, _bigint_heap.buffer);
  delete _bigint_stdlib.Math.imul;
} else {
  _bigint_asm = bigint_asm(_bigint_stdlib, null, _bigint_heap.buffer);
}

///////////////////////////////////////////////////////////////////////////////

const _BigNumber_ZERO_limbs = new Uint32Array(0);

export class BigNumber_constructor {
  /**
   * @param {BigNumber_constructor|string|number|Uint8Array} num
   * @return {BigNumber_constructor}
   */
  constructor(num) {
    let limbs = _BigNumber_ZERO_limbs;
    let bitlen = 0;
    let sign = 0;

    if (is_string(num)) num = string_to_bytes(num);

    if (is_buffer(num)) num = new Uint8Array(num);

    if (num === undefined) {
      // do nothing
    } else if (is_number(num)) {
      var absnum = Math.abs(num);
      if (absnum > 0xffffffff) {
        limbs = new Uint32Array(2);
        limbs[0] = absnum | 0;
        limbs[1] = (absnum / 0x100000000) | 0;
        bitlen = 52;
      } else if (absnum > 0) {
        limbs = new Uint32Array(1);
        limbs[0] = absnum;
        bitlen = 32;
      } else {
        limbs = _BigNumber_ZERO_limbs;
        bitlen = 0;
      }
      sign = num < 0 ? -1 : 1;
    } else if (is_bytes(num)) {
      for (var i = 0; !num[i]; i++);

      bitlen = (num.length - i) * 8;
      if (!bitlen) return BigNumber_ZERO;

      limbs = new Uint32Array((bitlen + 31) >> 5);
      for (var j = num.length - 4; j >= i; j -= 4) {
        limbs[(num.length - 4 - j) >> 2] = (num[j] << 24) | (num[j + 1] << 16) | (num[j + 2] << 8) | num[j + 3];
      }
      if (i - j === 3) {
        limbs[limbs.length - 1] = num[i];
      } else if (i - j === 2) {
        limbs[limbs.length - 1] = (num[i] << 8) | num[i + 1];
      } else if (i - j === 1) {
        limbs[limbs.length - 1] = (num[i] << 16) | (num[i + 1] << 8) | num[i + 2];
      }

      sign = 1;
    } else if (typeof num === 'object' && num !== null) {
      limbs = new Uint32Array(num.limbs);
      bitlen = num.bitLength;
      sign = num.sign;
    } else {
      throw new TypeError('number is of unexpected type');
    }

    this.limbs = limbs;
    this.bitLength = bitlen;
    this.sign = sign;
  }

  toString(radix) {
    radix = radix || 16;

    const limbs = this.limbs;
    const bitlen = this.bitLength;
    let str = '';

    if (radix === 16) {
      // FIXME clamp last limb to (bitlen % 32)
      for (var i = ((bitlen + 31) >> 5) - 1; i >= 0; i--) {
        var h = limbs[i].toString(16);
        str += '00000000'.substr(h.length);
        str += h;
      }

      str = str.replace(/^0+/, '');

      if (!str.length) str = '0';
    } else {
      throw new IllegalArgumentError('bad radix');
    }

    if (this.sign < 0) str = '-' + str;

    return str;
  }

  toBytes() {
    const bitlen = this.bitLength;
    const limbs = this.limbs;

    if (bitlen === 0) return new Uint8Array(0);

    const bytelen = (bitlen + 7) >> 3;
    const bytes = new Uint8Array(bytelen);
    for (let i = 0; i < bytelen; i++) {
      let j = bytelen - i - 1;
      bytes[i] = limbs[j >> 2] >> ((j & 3) << 3);
    }

    return bytes;
  }

  /**
   * Downgrade to Number
   *
   * @return {number}
   */
  valueOf() {
    const limbs = this.limbs;
    const bits = this.bitLength;
    const sign = this.sign;

    if (!sign) return 0;

    if (bits <= 32) return sign * (limbs[0] >>> 0);

    if (bits <= 52) return sign * (0x100000000 * (limbs[1] >>> 0) + (limbs[0] >>> 0));

    // normalization
    let i,
      l,
      e = 0;
    for (i = limbs.length - 1; i >= 0; i--) {
      if ((l = limbs[i]) === 0) continue;
      while (((l << e) & 0x80000000) === 0) e++;
      break;
    }

    if (i === 0) return sign * (limbs[0] >>> 0);

    return (
      sign *
      (0x100000 * (((limbs[i] << e) | (e ? limbs[i - 1] >>> (32 - e) : 0)) >>> 0) +
        (((limbs[i - 1] << e) | (e && i > 1 ? limbs[i - 2] >>> (32 - e) : 0)) >>> 12)) *
      Math.pow(2, 32 * i - e - 52)
    );
  }

  /**
   * @param {number} b
   * @return {BigNumber_constructor}
   */
  clamp(b) {
    const limbs = this.limbs;
    const bitlen = this.bitLength;

    // FIXME check b is number and in a valid range

    if (b >= bitlen) return this;

    const clamped = new BigNumber_constructor();
    let n = (b + 31) >> 5;
    let k = b % 32;

    clamped.limbs = new Uint32Array(limbs.subarray(0, n));
    clamped.bitLength = b;
    clamped.sign = this.sign;

    if (k) clamped.limbs[n - 1] &= -1 >>> (32 - k);

    return clamped;
  }

  /**
   * @param {number} f
   * @param {number} [b]
   * @return {BigNumber_constructor}
   */
  slice(f, b) {
    if (!is_number(f)) throw new TypeError('TODO');

    if (b !== undefined && !is_number(b)) throw new TypeError('TODO');

    const limbs = this.limbs;
    const bitlen = this.bitLength;

    if (f < 0) throw new RangeError('TODO');

    if (f >= bitlen) return BigNumber_ZERO;

    if (b === undefined || b > bitlen - f) b = bitlen - f;

    const sliced = new BigNumber_constructor();
    let n = f >> 5;
    let m = (f + b + 31) >> 5;
    let l = (b + 31) >> 5;
    let t = f % 32;
    let k = b % 32;

    const slimbs = new Uint32Array(l);
    if (t) {
      for (var i = 0; i < m - n - 1; i++) {
        slimbs[i] = (limbs[n + i] >>> t) | (limbs[n + i + 1] << (32 - t));
      }
      slimbs[i] = limbs[n + i] >>> t;
    } else {
      slimbs.set(limbs.subarray(n, m));
    }

    if (k) {
      slimbs[l - 1] &= -1 >>> (32 - k);
    }

    sliced.limbs = slimbs;
    sliced.bitLength = b;
    sliced.sign = this.sign;

    return sliced;
  }

  /**
   * @return {BigNumber_constructor}
   */
  negate() {
    const negative = new BigNumber_constructor();

    negative.limbs = this.limbs;
    negative.bitLength = this.bitLength;
    negative.sign = -1 * this.sign;

    return negative;
  }

  /**
   * @param {BigNumber_constructor} that
   * @return {number}
   */
  compare(that) {
    if (!is_big_number(that)) that = new BigNumber_constructor(that);

    var alimbs = this.limbs,
      alimbcnt = alimbs.length,
      blimbs = that.limbs,
      blimbcnt = blimbs.length,
      z = 0;

    if (this.sign < that.sign) return -1;

    if (this.sign > that.sign) return 1;

    _bigint_heap.set(alimbs, 0);
    _bigint_heap.set(blimbs, alimbcnt);
    z = _bigint_asm.cmp(0, alimbcnt << 2, alimbcnt << 2, blimbcnt << 2);

    return z * this.sign;
  }

  /**
   * @param {BigNumber_constructor} that
   * @return {BigNumber_constructor}
   */
  add(that) {
    if (!is_big_number(that)) that = new BigNumber_constructor(that);

    if (!this.sign) return that;

    if (!that.sign) return this;

    var abitlen = this.bitLength,
      alimbs = this.limbs,
      alimbcnt = alimbs.length,
      asign = this.sign,
      bbitlen = that.bitLength,
      blimbs = that.limbs,
      blimbcnt = blimbs.length,
      bsign = that.sign,
      rbitlen,
      rlimbcnt,
      rsign,
      rof,
      result = new BigNumber_constructor();

    rbitlen = (abitlen > bbitlen ? abitlen : bbitlen) + (asign * bsign > 0 ? 1 : 0);
    rlimbcnt = (rbitlen + 31) >> 5;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc(alimbcnt << 2),
      pB = _bigint_asm.salloc(blimbcnt << 2),
      pR = _bigint_asm.salloc(rlimbcnt << 2);

    _bigint_asm.z(pR - pA + (rlimbcnt << 2), 0, pA);

    _bigint_heap.set(alimbs, pA >> 2);
    _bigint_heap.set(blimbs, pB >> 2);

    if (asign * bsign > 0) {
      _bigint_asm.add(pA, alimbcnt << 2, pB, blimbcnt << 2, pR, rlimbcnt << 2);
      rsign = asign;
    } else if (asign > bsign) {
      rof = _bigint_asm.sub(pA, alimbcnt << 2, pB, blimbcnt << 2, pR, rlimbcnt << 2);
      rsign = rof ? bsign : asign;
    } else {
      rof = _bigint_asm.sub(pB, blimbcnt << 2, pA, alimbcnt << 2, pR, rlimbcnt << 2);
      rsign = rof ? asign : bsign;
    }

    if (rof) _bigint_asm.neg(pR, rlimbcnt << 2, pR, rlimbcnt << 2);

    if (_bigint_asm.tst(pR, rlimbcnt << 2) === 0) return BigNumber_ZERO;

    result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + rlimbcnt));
    result.bitLength = rbitlen;
    result.sign = rsign;

    return result;
  }

  /**
   * @param {BigNumber_constructor} that
   * @return {BigNumber_constructor}
   */
  subtract(that) {
    if (!is_big_number(that)) that = new BigNumber_constructor(that);

    return this.add(that.negate());
  }

  /**
   * @return {BigNumber_constructor}
   */
  square() {
    if (!this.sign) return BigNumber_ZERO;

    var abitlen = this.bitLength,
      alimbs = this.limbs,
      alimbcnt = alimbs.length,
      rbitlen,
      rlimbcnt,
      result = new BigNumber_constructor();

    rbitlen = abitlen << 1;
    rlimbcnt = (rbitlen + 31) >> 5;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc(alimbcnt << 2),
      pR = _bigint_asm.salloc(rlimbcnt << 2);

    _bigint_asm.z(pR - pA + (rlimbcnt << 2), 0, pA);

    _bigint_heap.set(alimbs, pA >> 2);

    _bigint_asm.sqr(pA, alimbcnt << 2, pR);

    result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + rlimbcnt));
    result.bitLength = rbitlen;
    result.sign = 1;

    return result;
  }

  /**
   * @param {BigNumber_constructor} that
   * @return {{quotient: BigNumber_constructor, remainder: BigNumber_constructor}}
   */
  divide(that) {
    if (!is_big_number(that)) that = new BigNumber_constructor(that);

    var abitlen = this.bitLength,
      alimbs = this.limbs,
      alimbcnt = alimbs.length,
      bbitlen = that.bitLength,
      blimbs = that.limbs,
      blimbcnt = blimbs.length,
      qlimbcnt,
      rlimbcnt,
      quotient = BigNumber_ZERO,
      remainder = BigNumber_ZERO;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc(alimbcnt << 2),
      pB = _bigint_asm.salloc(blimbcnt << 2),
      pQ = _bigint_asm.salloc(alimbcnt << 2);

    _bigint_asm.z(pQ - pA + (alimbcnt << 2), 0, pA);

    _bigint_heap.set(alimbs, pA >> 2);
    _bigint_heap.set(blimbs, pB >> 2);

    _bigint_asm.div(pA, alimbcnt << 2, pB, blimbcnt << 2, pQ);

    qlimbcnt = _bigint_asm.tst(pQ, alimbcnt << 2) >> 2;
    if (qlimbcnt) {
      quotient = new BigNumber_constructor();
      quotient.limbs = new Uint32Array(_bigint_heap.subarray(pQ >> 2, (pQ >> 2) + qlimbcnt));
      quotient.bitLength = abitlen < qlimbcnt << 5 ? abitlen : qlimbcnt << 5;
      quotient.sign = this.sign * that.sign;
    }

    rlimbcnt = _bigint_asm.tst(pA, blimbcnt << 2) >> 2;
    if (rlimbcnt) {
      remainder = new BigNumber_constructor();
      remainder.limbs = new Uint32Array(_bigint_heap.subarray(pA >> 2, (pA >> 2) + rlimbcnt));
      remainder.bitLength = bbitlen < rlimbcnt << 5 ? bbitlen : rlimbcnt << 5;
      remainder.sign = this.sign;
    }

    return {
      quotient: quotient,
      remainder: remainder,
    };
  }

  /**
   * @param {BigNumber_constructor} that
   * @return {BigNumber_constructor}
   */
  multiply(that) {
    if (!is_big_number(that)) that = new BigNumber_constructor(that);

    if (!this.sign || !that.sign) return BigNumber_ZERO;

    var abitlen = this.bitLength,
      alimbs = this.limbs,
      alimbcnt = alimbs.length,
      bbitlen = that.bitLength,
      blimbs = that.limbs,
      blimbcnt = blimbs.length,
      rbitlen,
      rlimbcnt,
      result = new BigNumber_constructor();

    rbitlen = abitlen + bbitlen;
    rlimbcnt = (rbitlen + 31) >> 5;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc(alimbcnt << 2),
      pB = _bigint_asm.salloc(blimbcnt << 2),
      pR = _bigint_asm.salloc(rlimbcnt << 2);

    _bigint_asm.z(pR - pA + (rlimbcnt << 2), 0, pA);

    _bigint_heap.set(alimbs, pA >> 2);
    _bigint_heap.set(blimbs, pB >> 2);

    _bigint_asm.mul(pA, alimbcnt << 2, pB, blimbcnt << 2, pR, rlimbcnt << 2);

    result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + rlimbcnt));
    result.sign = this.sign * that.sign;
    result.bitLength = rbitlen;

    return result;
  }

  /**
   * @param {number} rounds
   * @return {boolean}
   * @private
   */
  _isMillerRabinProbablePrime(rounds) {
    var t = new BigNumber_constructor(this),
      s = 0;
    t.limbs[0] -= 1;
    while (t.limbs[s >> 5] === 0) s += 32;
    while (((t.limbs[s >> 5] >> (s & 31)) & 1) === 0) s++;
    t = t.slice(s);

    var m = new Modulus(this),
      m1 = this.subtract(BigNumber_ONE),
      a = new BigNumber_constructor(this),
      l = this.limbs.length - 1;
    while (a.limbs[l] === 0) l--;

    while (--rounds >= 0) {
      Random_getValues(a.limbs);
      if (a.limbs[0] < 2) a.limbs[0] += 2;
      while (a.compare(m1) >= 0) a.limbs[l] >>>= 1;

      var x = m.power(a, t);
      if (x.compare(BigNumber_ONE) === 0) continue;
      if (x.compare(m1) === 0) continue;

      var c = s;
      while (--c > 0) {
        x = x.square().divide(m).remainder;
        if (x.compare(BigNumber_ONE) === 0) return false;
        if (x.compare(m1) === 0) break;
      }

      if (c === 0) return false;
    }

    return true;
  }

  /**
   * @param {number} paranoia
   * @return {boolean}
   */
  isProbablePrime(paranoia) {
    paranoia = paranoia || 80;

    var limbs = this.limbs,
      i = 0;

    // Oddity test
    // (50% false positive probability)
    if ((limbs[0] & 1) === 0) return false;
    if (paranoia <= 1) return true;

    // Magic divisors (3, 5, 17) test
    // (~25% false positive probability)
    var s3 = 0,
      s5 = 0,
      s17 = 0;
    for (i = 0; i < limbs.length; i++) {
      var l3 = limbs[i];
      while (l3) {
        s3 += l3 & 3;
        l3 >>>= 2;
      }

      var l5 = limbs[i];
      while (l5) {
        s5 += l5 & 3;
        l5 >>>= 2;
        s5 -= l5 & 3;
        l5 >>>= 2;
      }

      var l17 = limbs[i];
      while (l17) {
        s17 += l17 & 15;
        l17 >>>= 4;
        s17 -= l17 & 15;
        l17 >>>= 4;
      }
    }
    if (!(s3 % 3) || !(s5 % 5) || !(s17 % 17)) return false;
    if (paranoia <= 2) return true;

    // Miller-Rabin test
    // (≤ 4^(-k) false positive probability)
    return this._isMillerRabinProbablePrime(paranoia >>> 1);
  }
}

export const BigNumber_ZERO = new BigNumber_constructor(0);
export const BigNumber_ONE = new BigNumber_constructor(1);

/**
 * Returns an array populated with first n primes.
 *
 * @param {number} n
 * @return {number[]}
 * @private
 */
function _small_primes(n) {
  if (_primes.length >= n) return _primes.slice(0, n);

  for (let p = _primes[_primes.length - 1] + 2; _primes.length < n; p += 2) {
    for (var i = 0, d = _primes[i]; d * d <= p; d = _primes[++i]) {
      if (p % d == 0) break;
    }
    if (d * d > p) _primes.push(p);
  }

  return _primes;
}

/**
 * Returns strong pseudoprime of a specified bit length
 *
 * @param {number} bitlen
 * @param {function(p: BigNumber_constructor): number} filter
 * @return {BigNumber_constructor}
 */
export function randomProbablePrime(bitlen, filter) {
  let limbcnt = (bitlen + 31) >> 5;
  const prime = new BigNumber_constructor({ sign: 1, bitLength: bitlen, limbs: limbcnt });
  const limbs = prime.limbs;

  // Number of small divisors to try that minimizes the total cost of the trial division
  // along with the first round of Miller-Rabin test for a certain bit length.
  let k = 10000;
  if (bitlen <= 512) k = 2200;
  if (bitlen <= 256) k = 600;

  let divisors = _small_primes(k);
  const remainders = new Uint32Array(k);

  // Number of Miller-Rabin iterations for an error rate  of less than 2^-80
  // Damgaard, Landrock, Pomerance: Average case error estimates for the strong probable prime test.
  const s = (bitlen * Math.LN2) | 0;
  let r = 27;
  if (bitlen >= 250) r = 12;
  if (bitlen >= 450) r = 6;
  if (bitlen >= 850) r = 3;
  if (bitlen >= 1300) r = 2;

  while (true) {
    // populate `prime` with random bits, clamp to the appropriate bit length
    Random_getValues(limbs);
    limbs[0] |= 1;
    limbs[limbcnt - 1] |= 1 << ((bitlen - 1) & 31);
    if (bitlen & 31) limbs[limbcnt - 1] &= pow2_ceil((bitlen + 1) & 31) - 1;

    // remainders from division to small primes
    remainders[0] = 1;
    for (let i = 1; i < k; i++) {
      remainders[i] = prime.divide(divisors[i]).remainder.valueOf();
    }

    // try no more than `s` subsequent candidates
    seek: for (let j = 0; j < s; j += 2, limbs[0] += 2) {
      // check for small factors
      for (let i = 1; i < k; i++) {
        if ((remainders[i] + j) % divisors[i] === 0) continue seek;
      }

      // additional check just before the heavy lifting
      if (typeof filter === 'function' && !filter(prime)) continue;

      // proceed to Miller-Rabin test
      if (prime._isMillerRabinProbablePrime(r)) return prime;
    }
  }
}

export class Modulus extends BigNumber_constructor {
  /**
   * Modulus
   *
   * @param {BigNumber_constructor|string|number|Uint8Array} number
   */
  constructor(number) {
    super(number);

    if (this.valueOf() < 1) throw new RangeError();

    if (this.bitLength <= 32) return;

    let comodulus;

    if (this.limbs[0] & 1) {
      const bitlen = ((this.bitLength + 31) & -32) + 1;
      const limbs = new Uint32Array((bitlen + 31) >> 5);
      limbs[limbs.length - 1] = 1;
      comodulus = new BigNumber_constructor();
      comodulus.sign = 1;
      comodulus.bitLength = bitlen;
      comodulus.limbs = limbs;

      const k = Number_extGCD(0x100000000, this.limbs[0]).y;
      this.coefficient = k < 0 ? -k : 0x100000000 - k;
    } else {
      /**
       * TODO even modulus reduction
       * Modulus represented as `N = 2^U * V`, where `V` is odd and thus `GCD(2^U, V) = 1`.
       * Calculation `A = TR' mod V` is made as for odd modulo using Montgomery method.
       * Calculation `B = TR' mod 2^U` is easy as modulus is a power of 2.
       * Using Chinese Remainder Theorem and Garner's Algorithm restore `TR' mod N` from `A` and `B`.
       */
      return;
    }

    this.comodulus = comodulus;
    this.comodulusRemainder = comodulus.divide(this).remainder;
    this.comodulusRemainderSquare = comodulus.square().divide(this).remainder;
  }

  /**
   * Modular reduction
   *
   * @param {BigNumber_constructor} a
   * @return {BigNumber_constructor}
   * @constructor
   */
  reduce(a) {
    if (!is_big_number(a)) a = new BigNumber_constructor(a);

    if (a.bitLength <= 32 && this.bitLength <= 32) return new BigNumber_constructor(a.valueOf() % this.valueOf());

    if (a.compare(this) < 0) return a;

    return a.divide(this).remainder;
  }

  /**
   * Modular inverse
   *
   * @param {BigNumber_constructor} a
   * @return {BigNumber_constructor}
   * @constructor
   */
  inverse(a) {
    a = this.reduce(a);

    const r = BigNumber_extGCD(this, a);
    if (r.gcd.valueOf() !== 1) return null;

    if (r.y.sign < 0) return r.y.add(this).clamp(this.bitLength);

    return r.y;
  }

  /**
   * Modular exponentiation
   *
   * @param {BigNumber_constructor} g
   * @param {BigNumber_constructor} e
   * @return {BigNumber_constructor}
   * @constructor
   */
  power(g, e) {
    if (!is_big_number(g)) g = new BigNumber_constructor(g);

    if (!is_big_number(e)) e = new BigNumber_constructor(e);

    // count exponent set bits
    let c = 0;
    for (let i = 0; i < e.limbs.length; i++) {
      let t = e.limbs[i];
      while (t) {
        if (t & 1) c++;
        t >>>= 1;
      }
    }

    // window size parameter
    let k = 8;
    if (e.bitLength <= 4536) k = 7;
    if (e.bitLength <= 1736) k = 6;
    if (e.bitLength <= 630) k = 5;
    if (e.bitLength <= 210) k = 4;
    if (e.bitLength <= 60) k = 3;
    if (e.bitLength <= 12) k = 2;
    if (c <= 1 << (k - 1)) k = 1;

    // montgomerize base
    g = _Montgomery_reduce(this.reduce(g).multiply(this.comodulusRemainderSquare), this);

    // precompute odd powers
    const g2 = _Montgomery_reduce(g.square(), this),
      gn = new Array(1 << (k - 1));
    gn[0] = g;
    gn[1] = _Montgomery_reduce(g.multiply(g2), this);
    for (let i = 2; i < 1 << (k - 1); i++) {
      gn[i] = _Montgomery_reduce(gn[i - 1].multiply(g2), this);
    }

    // perform exponentiation
    const u = this.comodulusRemainder;
    let r = u;
    for (let i = e.limbs.length - 1; i >= 0; i--) {
      let t = e.limbs[i];
      for (let j = 32; j > 0; ) {
        if (t & 0x80000000) {
          let n = t >>> (32 - k),
            l = k;
          while ((n & 1) === 0) {
            n >>>= 1;
            l--;
          }
          var m = gn[n >>> 1];
          while (n) {
            n >>>= 1;
            if (r !== u) r = _Montgomery_reduce(r.square(), this);
          }
          r = r !== u ? _Montgomery_reduce(r.multiply(m), this) : m;
          (t <<= l), (j -= l);
        } else {
          if (r !== u) r = _Montgomery_reduce(r.square(), this);
          (t <<= 1), j--;
        }
      }
    }

    // de-montgomerize result
    return _Montgomery_reduce(r, this);
  }
}

/**
 * @param {BigNumber_constructor} a
 * @param {BigNumber_constructor} n
 * @return {BigNumber_constructor}
 * @private
 */
function _Montgomery_reduce(a, n) {
  const alimbs = a.limbs;
  const alimbcnt = alimbs.length;
  const nlimbs = n.limbs;
  const nlimbcnt = nlimbs.length;
  const y = n.coefficient;

  _bigint_asm.sreset();

  const pA = _bigint_asm.salloc(alimbcnt << 2),
    pN = _bigint_asm.salloc(nlimbcnt << 2),
    pR = _bigint_asm.salloc(nlimbcnt << 2);

  _bigint_asm.z(pR - pA + (nlimbcnt << 2), 0, pA);

  _bigint_heap.set(alimbs, pA >> 2);
  _bigint_heap.set(nlimbs, pN >> 2);

  _bigint_asm.mredc(pA, alimbcnt << 2, pN, nlimbcnt << 2, y, pR);

  const result = new BigNumber_constructor();
  result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + nlimbcnt));
  result.bitLength = n.bitLength;
  result.sign = 1;

  return result;
}
