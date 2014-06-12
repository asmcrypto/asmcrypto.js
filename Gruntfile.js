// Default modules to build
var defaults = [
    'utils',
    'aes-cbc',
    'aes-ccm',
    'sha1',
    'sha256',
    'hmac-sha1',
    'hmac-sha256',
    'pbkdf2-hmac-sha1',
    'pbkdf2-hmac-sha256',
    'rng',
    'bn',
    'rsa-pkcs1',
    'globals-rng',
    'globals'
];

// Map each of the modules and their deps
// Topo-sorted
var modules = {
    'common': {
        files: [ 'src/errors.js' ]
    },
    'utils': {
        files: [ 'src/utils.js' ],
        implies: [ 'exports' ]
    },
    'aes': {
        files: [ 'src/aes/aes.asm.js', 'src/aes/aes.js' ],
        depends: [ 'common', 'utils' ]
    },
    'aes-cbc': {
        files: [ 'src/aes/aes-cbc.js' ],
        depends: [ 'aes' ],
        implies: [ 'exports-aes' ]
    },
    'aes-ccm': {
        files: [ 'src/aes/aes-ccm.js' ],
        depends: [ 'aes' ],
        implies: [ 'exports-aes' ]
    },
    'aes-cfb': {
        files: [ 'src/aes/aes-cfb.js' ],
        depends: [ 'aes' ],
        implies: [ 'exports-aes' ]
    },
    'exports-aes': {
        files: [ 'src/aes/exports.js' ],
        depends: [ 'aes' ]
    },
    'sha1': {
        files: [ 'src/sha1/sha1.asm.js', 'src/sha1/sha1.js' ],
        depends: [ 'common', 'utils' ],
        implies: [ 'exports-sha1' ]
    },
    'exports-sha1': {
        files: [ 'src/sha1/exports.js' ],
        depends: [ 'sha1' ]
    },
    'sha256': {
        files: [ 'src/sha256/sha256.asm.js', 'src/sha256/sha256.js' ],
        depends: [ 'common', 'utils' ],
        implies: [ 'exports-sha256' ]
    },
    'exports-sha256': {
        files: [ 'src/sha256/exports.js' ],
        depends: [ 'sha256' ],
    },
    'sha512': {
        files: [ 'src/sha512/sha512.asm.js', 'src/sha512/sha512.js' ],
        depends: [ 'common', 'utils' ],
        implies: [ 'exports-sha512' ]
    },
    'exports-sha512': {
        files: [ 'src/sha512/exports.js' ],
        depends: [ 'sha512' ]
    },
    'hmac': {
        files: [ 'src/hmac/hmac.js' ],
        depends: [ 'common', 'utils' ]
    },
    'hmac-sha1': {
        files: [ 'src/hmac/hmac-sha1.js' ],
        depends: [ 'hmac', 'sha1' ],
        implies: [ 'exports-hmac' ]
    },
    'hmac-sha256': {
        files: [ 'src/hmac/hmac-sha256.js' ],
        depends: [ 'hmac', 'sha256' ],
        implies: [ 'exports-hmac' ]
    },
    'hmac-sha512': {
        files: [ 'src/hmac/hmac-sha512.js' ],
        depends: [ 'hmac', 'sha512' ],
        implies: [ 'exports-hmac' ]
    },
    'exports-hmac': {
        files: [ 'src/hmac/exports.js' ],
        depends: [ 'hmac' ]
    },
    'pbkdf2': {
        files: [ 'src/pbkdf2/pbkdf2.js' ],
        depends: [ 'common', 'utils' ]
    },
    'pbkdf2-hmac-sha1': {
        files: [ 'src/pbkdf2/pbkdf2-hmac-sha1.js' ],
        depends: [ 'pbkdf2', 'hmac-sha1' ],
        implies: [ 'exports-pbkdf2' ]
    },
    'pbkdf2-hmac-sha256': {
        files: [ 'src/pbkdf2/pbkdf2-hmac-sha256.js' ],
        depends: [ 'pbkdf2', 'hmac-sha256' ],
        implies: [ 'exports-pbkdf2' ]
    },
    'pbkdf2-hmac-sha512': {
        files: [ 'src/pbkdf2/pbkdf2-hmac-sha512.js' ],
        implies: [ 'exports-pbkdf2' ],
        depends: [ 'pbkdf2', 'hmac-sha512' ]
    },
    'exports-pbkdf2': {
        files: [ 'src/pbkdf2/exports.js' ],
        depends: [ 'pbkdf2' ]
    },
    'rng': {
        files: [ 'src/random/isaac.js', 'src/random/random.js' ],
        depends: [ 'common', 'utils' ],
        implies: [ 'exports-rng' ]
    },
    'exports-rng': {
        files: [ 'src/random/exports.js' ],
        depends: [ 'rng' ]
    },
    'globals-rng': {
        files: [ 'src/random/globals.js' ],
        depends: [ 'rng' ]
    },
    'bn': {
        files: [ 'src/bignum/bigint.asm.js', 'src/bignum/bignum.js', 'src/bignum/extgcd.js', 'src/bignum/modulus.js', 'src/bignum/prime.js' ],
        depends: [ 'common', 'rng' ],
        implies: [ 'exports-bn' ]
    },
    'exports-bn': {
        files: [ 'src/bignum/exports.js' ],
        depends: [ 'bn' ]
    },
    'rsa': {
        files: [ 'src/rsa/rsa.js', 'src/rsa/genkey.js' ],
        depends: [ 'bn', 'rng' ]
    },
    'rsa-pkcs1': {
        files: [ 'src/rsa/pkcs1.js' ],
        depends: [ 'rsa' ],
        implies: [ 'exports-rsa' ]
    },
    'exports-rsa': {
        files: [ 'src/rsa/exports.js' ],
        depends: [ 'rsa' ]
    },
    'exports': {
        files: [ 'src/exports.js' ],
        depends: [ 'utils' ]
    },
    'globals': {
        files: [ 'src/globals.js' ],
        depends: [ 'common' ]
    }
};

// Supported browsers
var browsers = [
    // Latest browsers
    {
        browserName: 'Firefox',
    },
    {
        browserName: 'Chrome',
    },
    {
        browserName: 'Internet Explorer',
    },
    {
        browserName: 'Opera',
    },
    {
        browserName: 'Safari',
        platform: 'OS X 10.9'
    },
    // Legacy browsers
    {
        browserName: 'Firefox',
        version: '22'
    },
    {
        browserName: 'Internet Explorer',
        version: '10'
    },
    {
        browserName: 'Safari',
        platform: 'OS X 10.8'
    },
    {
        browserName: 'Safari',
        platform: 'OS X 10.6'
    }
];

// Grunt setup
module.exports = function ( grunt ) {
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-connect');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-saucelabs');

    // Get the list of modules split by commas
    var includeModules = ( grunt.option('with') || process.env.WITH || '' ).split(',')
                        .map( function ( moduleName ) { return moduleName.trim() } )
                        .filter( function ( moduleName ) { return moduleName.length > 0 } );

    // No modules specified, put defaults here
    if ( includeModules.length === 0 )
        includeModules = includeModules.concat(defaults);

    // Insert implied modules for each one specified
    for ( var i = includeModules.length-1; i >= 0; i-- ) {
        if ( !modules[ includeModules[i] ] || !modules[ includeModules[i] ].implies ) continue;
        var includeImplied = modules[ includeModules[i] ].implies.filter( function ( m ) { return includeModules.indexOf(m) == -1 } );
        includeModules.splice.apply( includeModules, [ i+1, 0 ].concat(includeImplied) );
    }

    // Trace build configuration
    grunt.log.writeln( "Building modules: " + includeModules.join(", ") );

    // Recurse into dependancy tree
    function getDeepDependancies ( moduleName ) {
        var module = modules[moduleName];
        if ( !module )
            grunt.fail.fatal( "An unknown module '" + moduleName + "' specified" );

        // Get the deps and call recursively
        var deps = module.depends || [];

        deps = deps.reduce(
            function ( list, m ) {
                list.push.apply( list, getDeepDependancies(m) );
                return list;
            },
            []
        ).concat(deps);

        // Return flattened dependencies
        return deps;
    }

    // Loop each of the specified module names
    includeModules = includeModules.reduce(
        function ( list, m ) {
            list.push.apply( list, getDeepDependancies(m) );
            return list;
        },
        []
    ).concat(includeModules);

    // Hold the array of files as specified by the modules
    var src = [];
    for ( var moduleName in modules ) {
        var module = modules[moduleName];
        if ( includeModules.indexOf(moduleName) === -1 ) continue;
        src.push.apply( src, module.files );
    }

    // Finally, configure
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        uglify: {
            devel: {
                options: {
                    mangle: false,
                    compress: false,
                    beautify: true,
                    sourceMap: 'asmcrypto.js.map',
                    wrap: 'asmCrypto'
                },
                files: {
                    'asmcrypto.js': src
                }
            },
            release: {
                options: {
                    mangle: true,
                    compress: true,
                    beautify: false,
                    sourceMap: 'asmcrypto.js.map',
                    wrap: 'asmCrypto'
                },
                files: {
                    'asmcrypto.js': src
                }
            }
        },

        qunit: {
            all: ['test/index.html']
        },

        'saucelabs-qunit': {
            all: {
                options: {
                    testname: 'asmcrypto.js',
                    urls: [ 'http://localhost:9999/' ],
                    browsers: browsers,
                    build: process.env.TRAVIS_JOB_ID
                }
            }
        },

        connect: {
            all: {
                options: {
                    hostname: 'localhost',
                    port: 9999,
                    base: 'test'
                }
            }
        },

        watch: {
            all: {
                files: src,
                tasks: ['uglify:devel']
            }
        },

        clean: [
            'asmcrypto.js',
            'asmcrypto.js.map'
        ]
    });

    grunt.registerTask('default', ['uglify:release']);
    grunt.registerTask('devel', ['uglify:devel','connect','watch']);
    grunt.registerTask('test', ['qunit']);
    grunt.registerTask('sauce', ['connect','saucelabs-qunit']);
};
