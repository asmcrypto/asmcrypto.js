declare interface bigintresult {
  sreset: (n?: number) => number;
  salloc: (n?: number) => number;
  sfree: (n?: number) => void;
  z: (l?: number, z?: number, A?: number) => void;
  tst: (A?: number, lA?: number) => 0;
  neg: (A?: number, lA?: number, R?: number, lR?: number) => number;
  cmp: (A?: number, lA?: number, B?: number, lB?: number) => 0;
  add: (
    A?: number,
    lA?: number,
    B?: number,
    lB?: number,
    R?: number,
    lR?: number,
  ) => number;
  sub: (
    A?: number,
    lA?: number,
    B?: number,
    lB?: number,
    R?: number,
    lR?: number,
  ) => number;
  mul: (
    A?: number,
    lA?: number,
    B?: number,
    lB?: number,
    R?: number,
    lR?: number,
  ) => void;
  sqr: (A?: number, lA?: number, R?: number) => void;
  div: (
    N?: number,
    lN?: number,
    D?: number,
    lD?: number,
    Q?: number,
  ) => void;
  mredc: (
    A?: number,
    lA?: number,
    N?: number,
    lN?: number,
    y?: number,
    R?: number,
  ) => void;
}

export function bigint_asm(stdlib: any, foreign: any, buffer: ArrayBuffer): bigintresult;
