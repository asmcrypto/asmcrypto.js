declare class BigNumber {
  static ZERO: BigNumber;
  static ONE: BigNumber;

  constructor(num?: Uint8Array);

  toString(radix?: number): string;

  toBytes(): Uint8Array;

  valueOf(): number;

  clamp(b: number): BigNumber;

  slice(f: number, b: number): BigNumber;

  negate(): BigNumber;

  compare(that: BigNumber): 0 | 1 | -1;

  add(that: BigNumber): BigNumber;

  subtract(that: BigNumber): BigNumber;

  multiply(that: BigNumber): BigNumber;

  square(): BigNumber;

  divide(that: BigNumber): BigNumber;
}

declare class AES {
  BLOCK_SIZE: number;
  result: Uint8Array;

  constructor(key: Uint8Array, iv?: Uint8Array, padding?: boolean, heap?: Uint8Array, asm?: Uint8Array);
}

declare interface AES_reset<M> {
  (key: Uint8Array, iv?: Uint8Array, padding?: boolean): M;
}

declare interface AES_Encrypt_finish<M> {
  (data?: Uint8Array): M;
}

declare interface AES_Decrypt_finish<M> {
  (data?: Uint8Array): M;
}

declare interface AES_Encrypt_process<M> {
  (data: Uint8Array): M;
}

declare interface AES_Decrypt_process<M> {
  (data: Uint8Array): M;
}

declare interface RSA_OAEP_Encrypt {
  (data: Uint8Array, key: BigNumber[], label?: Uint8Array): Uint8Array;
}

declare interface RSA_OAEP_Decrypt {
  (data: Uint8Array, key: BigNumber[], label?: Uint8Array): Uint8Array;
}

declare interface RSA_PSS_Sign {
  (data: Uint8Array, key: BigNumber[], slen?: number): Uint8Array;
}

declare interface RSA_PSS_Verify {
  (signature: Uint8Array, data: Uint8Array, key: BigNumber[], slen?: number): boolean;
}

declare class AES_ECB_Encrypt extends AES {
  constructor(key: Uint8Array, heap?: Uint8Array);

  reset: AES_reset<AES_ECB_Encrypt>;
  process: AES_Encrypt_process<AES_ECB_Encrypt>;
  finish: AES_Encrypt_finish<AES_ECB_Encrypt>;
}

declare class AES_ECB extends AES {
  constructor(key: Uint8Array, heap?: Uint8Array, asm?: Uint8Array);

  encrypt: AES_Encrypt_finish<AES_ECB>;
  decrypt: AES_Decrypt_finish<AES_ECB>;
}

declare class AES_ECB_Decrypt extends AES {
  constructor(key: Uint8Array, heap?: Uint8Array);

  reset: AES_reset<AES_ECB_Decrypt>;
  process: AES_Encrypt_process<AES_ECB_Decrypt>;
  finish: AES_Decrypt_finish<AES_ECB_Decrypt>;
}

declare class AES_CBC_Encrypt extends AES {
  constructor(key: Uint8Array, iv: Uint8Array, padding?: boolean, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_CBC_Encrypt>;
  process: AES_Encrypt_process<AES_CBC_Encrypt>;
  finish: AES_Encrypt_finish<AES_CBC_Encrypt>;
}

declare class AES_CBC_Decrypt extends AES {
  constructor(key: Uint8Array, iv: Uint8Array, padding?: boolean, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_CBC_Decrypt>;
  process: AES_Encrypt_process<AES_CBC_Decrypt>;
  finish: AES_Decrypt_finish<AES_CBC_Decrypt>;
}

declare class AES_CCM_Encrypt extends AES {
  constructor(key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, dataLength?: number, tagSize?: number, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_CCM_Encrypt>;
  process: AES_Encrypt_process<AES_CCM_Encrypt>;
  finish: AES_Encrypt_finish<AES_CCM_Encrypt>;
}

declare class AES_CCM_Decrypt extends AES {
  constructor(key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, dataLength?: number, tagSize?: number, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_CCM_Decrypt>;
  process: AES_Encrypt_process<AES_CCM_Decrypt>;
  finish: AES_Decrypt_finish<AES_CCM_Decrypt>;
}

declare class AES_CFB_Encrypt extends AES {
  constructor(key: Uint8Array, iv?: Uint8Array, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_CFB_Encrypt>;
  process: AES_Encrypt_process<AES_CFB_Encrypt>;
  finish: AES_Encrypt_finish<AES_CFB_Encrypt>;
}

declare class AES_CFB_Decrypt extends AES {
  constructor(key: Uint8Array, iv?: Uint8Array, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_CFB_Decrypt>;
  process: AES_Encrypt_process<AES_CFB_Decrypt>;
  finish: AES_Decrypt_finish<AES_CFB_Decrypt>;
}

declare class AES_GCM_Encrypt extends AES {
  constructor(key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, tagSize?: number, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_GCM_Encrypt>;
  process: AES_Encrypt_process<AES_GCM_Encrypt>;
  finish: AES_Encrypt_finish<AES_GCM_Encrypt>;
}

declare class AES_GCM_Decrypt extends AES {
  constructor(key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, tagSize?: number, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_GCM_Decrypt>;
  process: AES_Encrypt_process<AES_GCM_Decrypt>;
  finish: AES_Decrypt_finish<AES_GCM_Decrypt>;
}

declare class AES_OFB extends AES {
  constructor(key: Uint8Array, iv?: Uint8Array, heap?: Uint8Array, asm?: Uint8Array);

  reset: AES_reset<AES_OFB>;
  process: AES_Encrypt_process<AES_OFB>;
  finish: AES_Encrypt_finish<AES_OFB>;
}

declare class AES_CTR extends AES {
  constructor(key: Uint8Array, nonce: Uint8Array, heap?: Uint8Array, asm?: Uint8Array);

  reset(key: Uint8Array, nonce: Uint8Array, counter?: number, counterSize?: number): AES_CTR;

  process: AES_Encrypt_process<AES_CTR>;
  finish: AES_Encrypt_finish<AES_CTR>;
}

declare class AES_CBC {
  static encrypt: (data: Uint8Array, key: Uint8Array, padding?: boolean, iv?: Uint8Array) => Uint8Array;
  static decrypt: (data: Uint8Array, key: Uint8Array, padding?: boolean, iv?: Uint8Array) => Uint8Array;
}

declare class AES_CCM {
  static encrypt: (data: Uint8Array, key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, tagSize?: number) => Uint8Array;
  static decrypt: (data: Uint8Array, key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, tagSize?: number) => Uint8Array;
}

declare class AES_CFB {
  static encrypt: (data: Uint8Array, key: Uint8Array, iv?: Uint8Array) => Uint8Array;
  static decrypt: (data: Uint8Array, key: Uint8Array, iv?: Uint8Array) => Uint8Array;
}

declare class AES_CTR {
  static encrypt: (data: Uint8Array, key: Uint8Array, nonce: Uint8Array) => Uint8Array;
  static decrypt: (data: Uint8Array, key: Uint8Array, nonce: Uint8Array) => Uint8Array;
}

declare class AES_OFB {
  static encrypt: (data: Uint8Array, key: Uint8Array, iv?: Uint8Array) => Uint8Array;
  static decrypt: (data: Uint8Array, key: Uint8Array, iv?: Uint8Array) => Uint8Array;
}

declare class AES_GCM {
  static encrypt: (data: Uint8Array, key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, tagSize?: number) => Uint8Array;
  static decrypt: (data: Uint8Array, key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, tagSize?: number) => Uint8Array;
}

declare class SHA1 {
  result: Uint8Array;

  static bytes(data: Uint8Array): Uint8Array;

  static hex(data: Uint8Array): string;

  static base64(data: Uint8Array): string;

  constructor(options?: { asm?: Uint8Array, heap?: Uint8Array, heapSize?: number });

  reset(): SHA1;

  process(data: Uint8Array): SHA1;

  finish(): SHA1;
}

declare class SHA256 {
  result: Uint8Array;

  static bytes(data: Uint8Array): Uint8Array;

  static hex(data: Uint8Array): string;

  static base64(data: Uint8Array): string;

  constructor(options?: { asm?: Uint8Array, heap?: Uint8Array, heapSize?: number });

  reset(): SHA256;

  process(data: Uint8Array): SHA256;

  finish(): SHA256;
}

declare class SHA512 {
  result: Uint8Array;

  static bytes(data: Uint8Array): Uint8Array;

  static hex(data: Uint8Array): string;

  static base64(data: Uint8Array): string;

  constructor(options?: { asm?: Uint8Array, heap?: Uint8Array, heapSize?: number });

  reset(): SHA512;

  process(data: Uint8Array): SHA512;

  finish(): SHA512;
}

declare class HMAC_SHA1 {
  result: Uint8Array;

  static bytes(data: Uint8Array, password: Uint8Array): Uint8Array;

  static hex(data: Uint8Array, password: Uint8Array): string;

  static base64(data: Uint8Array, password: Uint8Array): string;

  constructor(options?: { asm?: Uint8Array, heap?: Uint8Array, heapSize?: number, password?: Uint8Array, hash?: SHA1 });

  reset(options: { password: Uint8Array }): HMAC_SHA1;

  process(data: Uint8Array): HMAC_SHA1;

  finish(): HMAC_SHA1;
}

declare class HMAC_SHA256 {
  result: Uint8Array;

  static bytes(data: Uint8Array, password: Uint8Array): Uint8Array;

  static hex(data: Uint8Array, password: Uint8Array): string;

  static base64(data: Uint8Array, password: Uint8Array): string;

  constructor(options?: { asm?: Uint8Array, heap?: Uint8Array, heapSize?: number, password?: Uint8Array, hash?: SHA256 });

  reset(options: { password: Uint8Array }): HMAC_SHA256;

  process(data: Uint8Array): HMAC_SHA256;

  finish(): HMAC_SHA256;
}

declare class HMAC_SHA512 {
  result: Uint8Array;

  static bytes(data: Uint8Array, password: Uint8Array): Uint8Array;

  static hex(data: Uint8Array, password: Uint8Array): string;

  static base64(data: Uint8Array, password: Uint8Array): string;

  constructor(options?: { asm?: Uint8Array, heap?: Uint8Array, heapSize?: number, password?: Uint8Array, hash?: SHA512 });

  reset(options: { password: Uint8Array }): HMAC_SHA512;

  process(data: Uint8Array): HMAC_SHA512;

  finish(): HMAC_SHA512;
}

declare class PBKDF2_HMAC_SHA1 {
  static bytes(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;

  static hex(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;

  static base64(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;
}

declare class PBKDF2_HMAC_SHA256 {
  static bytes(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;

  static hex(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;

  static base64(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;
}

declare class PBKDF2_HMAC_SHA512 {
  static bytes(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;

  static hex(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;

  static base64(password: Uint8Array, salt: Uint8Array, iterations?: number, dklen?: number): Uint8Array;
}

declare class RSA_OAEP_SHA1 {
  static encrypt: RSA_OAEP_Encrypt;
  static decrypt: RSA_OAEP_Decrypt;
}

declare class RSA_OAEP_SHA256 {
  static encrypt: RSA_OAEP_Encrypt;
  static decrypt: RSA_OAEP_Decrypt;
}

declare class RSA_OAEP_SHA512 {
  static encrypt: RSA_OAEP_Encrypt;
  static decrypt: RSA_OAEP_Decrypt;
}

declare class RSA_PSS_SHA1 {
  static sign: RSA_PSS_Sign;
  static verify: RSA_PSS_Verify;
}

declare class RSA_PSS_SHA256 {
  static sign: RSA_PSS_Sign;
  static verify: RSA_PSS_Verify;
}

declare class RSA_PSS_SHA512 {
  static sign: RSA_PSS_Sign;
  static verify: RSA_PSS_Verify;
}

declare function random(): number;

declare namespace random {
  export function seed(data: Uint8Array): boolean;
}


declare function string_to_bytes(s: string): Uint8Array;

declare function hex_to_bytes(s: string): Uint8Array;

declare function base64_to_bytes(s: string): Uint8Array;

declare function bytes_to_string(bytes: Uint8Array): string;

declare function bytes_to_hex(bytes: Uint8Array): string;

declare function bytes_to_base64(bytes: Uint8Array): string;
