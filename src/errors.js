function IllegalStateError () { Error.apply( this, arguments ); }
IllegalStateError.prototype = new Error;

function IllegalArgumentError () { Error.apply( this, arguments ); }
IllegalArgumentError.prototype = new Error;

function SecurityError () { Error.apply( this, arguments ); }
IllegalArgumentError.prototype = new Error;
