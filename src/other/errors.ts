export class IllegalStateError extends Error {
  constructor(...args: any[]) {
    super(...args);
    Object.create(Error.prototype, { name: { value: 'IllegalStateError' } });
  }
}

export class IllegalArgumentError extends Error {
  constructor(...args: any[]) {
    super(...args);
    Object.create(Error.prototype, { name: { value: 'IllegalArgumentError' } });
  }
}

export class SecurityError extends Error {
  constructor(...args: any[]) {
    super(...args);
    Object.create(Error.prototype, { name: { value: 'SecurityError' } });
  }
}
