export function IllegalStateError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
IllegalStateError.prototype = Object.create( Error.prototype, { name: { value: 'IllegalStateError' } } );

export function IllegalArgumentError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
IllegalArgumentError.prototype = Object.create( Error.prototype, { name: { value: 'IllegalArgumentError' } } );

export function SecurityError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
SecurityError.prototype = Object.create( Error.prototype, { name: { value: 'SecurityError' } } );
