exports.random = Random_getNumber;

exports.random.seed = Random_seed;

Object.defineProperty( Random_getNumber, 'allowWeak', {
    get: function () { return _random_allow_weak; },
    set: function ( a ) { _random_allow_weak = a; }
});

Object.defineProperty( Random_getNumber, 'skipSystemRNGWarning', {
    get: function () { return _random_skip_system_rng_warning; },
    set: function ( w ) { _random_skip_system_rng_warning = w; }
});

exports.getRandomValues = Random_getValues;

exports.getRandomValues.seed = Random_seed;

Object.defineProperty( Random_getValues, 'allowWeak', {
    get: function () { return _random_allow_weak; },
    set: function ( a ) { _random_allow_weak = a; }
});

Object.defineProperty( Random_getValues, 'skipSystemRNGWarning', {
    get: function () { return _random_skip_system_rng_warning; },
    set: function ( w ) { _random_skip_system_rng_warning = w; }
});
