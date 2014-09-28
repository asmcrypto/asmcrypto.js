// Default modules to build
var defaults = [
    'utils',
    'globals',
    'aes-cbc',
    'aes-gcm',
    'sha1',
    'sha256',
    'sha512',
    'hmac-sha1',
    'hmac-sha256',
    'hmac-sha512',
    'pbkdf2-hmac-sha1',
    'pbkdf2-hmac-sha256',
    'pbkdf2-hmac-sha512',
    'rng',
    'bn',
    'rsa-pkcs1',
    'rng-globals'
];

// Map each of the modules and their deps
// Topo-sorted
var modules = [
    {
        name: 'common',
        files: [ 'src/errors.js' ]
    },
    {
        name: 'utils',
        files: [ 'src/utils.js' ],
        implies: [ 'exports' ]
    },
    {
        name: 'exports',
        files: [ 'src/exports.js' ],
        depends: [ 'utils' ]
    },
    {
        name: 'globals',
        files: [ 'src/globals.js' ],
        depends: [ 'common' ]
    },
    {
        name: 'aes',
        files: [ 'src/aes/aes.asm.js', 'src/aes/aes.js' ],
        depends: [ 'common', 'utils' ]
    },
    {
        name: 'aes-ecb',
        files: [ 'src/aes/aes-ecb.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-ecb-exports' ]
    },
    {
        name: 'aes-cbc',
        files: [ 'src/aes/aes-cbc.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-cbc-exports' ]
    },
    {
        name: 'aes-cfb',
        files: [ 'src/aes/aes-cfb.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-cfb-exports' ]
    },
    {
        name: 'aes-ctr',
        files: [ 'src/aes/aes-ctr.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-ctr-exports' ]
    },
    {
        name: 'aes-ccm',
        files: [ 'src/aes/aes-ccm.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-ccm-exports' ]
    },
    {
        name: 'aes-gcm',
        files: [ 'src/aes/aes-gcm.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-gcm-exports' ]
    },
    {
        name: 'aes-exports',
        files: [ 'src/aes/exports.js' ],
        depends: [ 'aes' ]
    },
    {
        name: 'aes-ecb-exports',
        files: [ 'src/aes/exports-ecb.js' ],
        depends: [ 'aes-ecb', 'aes-exports' ]
    },
    {
        name: 'aes-cbc-exports',
        files: [ 'src/aes/exports-cbc.js' ],
        depends: [ 'aes-cbc', 'aes-exports' ]
    },
    {
        name: 'aes-cfb-exports',
        files: [ 'src/aes/exports-cfb.js' ],
        depends: [ 'aes-cfb', 'aes-exports' ]
    },
    {
        name: 'aes-ctr-exports',
        files: [ 'src/aes/exports-ctr.js' ],
        depends: [ 'aes-ctr', 'aes-exports' ]
    },
    {
        name: 'aes-ccm-exports',
        files: [ 'src/aes/exports-ccm.js' ],
        depends: [ 'aes-ccm', 'aes-exports' ]
    },
    {
        name: 'aes-gcm-exports',
        files: [ 'src/aes/exports-gcm.js' ],
        depends: [ 'aes-gcm', 'aes-exports' ]
    },
    {
        name: 'sha1',
        files: [ 'src/sha1/sha1.asm.js', 'src/sha1/sha1.js' ],
        depends: [ 'common', 'utils' ],
        implies: [ 'sha1-exports' ]
    },
    {
        name: 'sha1-exports',
        files: [ 'src/sha1/exports.js' ],
        depends: [ 'sha1' ]
    },
    {
        name: 'sha256',
        files: [ 'src/sha256/sha256.asm.js', 'src/sha256/sha256.js' ],
        depends: [ 'common', 'utils' ],
        implies: [ 'sha256-exports' ]
    },
    {
        name: 'sha256-exports',
        files: [ 'src/sha256/exports.js' ],
        depends: [ 'sha256' ],
    },
    {
        name: 'sha512',
        files: [ 'src/sha512/sha512.asm.js', 'src/sha512/sha512.js' ],
        depends: [ 'common', 'utils' ],
        implies: [ 'sha512-exports' ]
    },
    {
        name: 'sha512-exports',
        files: [ 'src/sha512/exports.js' ],
        depends: [ 'sha512' ]
    },
    {
        name: 'hmac',
        files: [ 'src/hmac/hmac.js' ],
        depends: [ 'common', 'utils' ]
    },
    {
        name: 'hmac-sha1',
        files: [ 'src/hmac/hmac-sha1.js' ],
        depends: [ 'hmac', 'sha1' ],
        implies: [ 'hmac-sha1-exports' ]
    },
    {
        name: 'hmac-sha256',
        files: [ 'src/hmac/hmac-sha256.js' ],
        depends: [ 'hmac', 'sha256' ],
        implies: [ 'hmac-sha256-exports' ]
    },
    {
        name: 'hmac-sha512',
        files: [ 'src/hmac/hmac-sha512.js' ],
        depends: [ 'hmac', 'sha512' ],
        implies: [ 'hmac-sha512-exports' ]
    },
    {
        name: 'hmac-sha1-exports',
        files: [ 'src/hmac/exports-hmac-sha1.js' ],
        depends: [ 'hmac-sha1' ]
    },
    {
        name: 'hmac-sha256-exports',
        files: [ 'src/hmac/exports-hmac-sha256.js' ],
        depends: [ 'hmac-sha256' ]
    },
    {
        name: 'hmac-sha512-exports',
        files: [ 'src/hmac/exports-hmac-sha512.js' ],
        depends: [ 'hmac-sha512' ]
    },
    {
        name: 'pbkdf2',
        files: [ 'src/pbkdf2/pbkdf2.js' ],
        depends: [ 'common', 'utils' ]
    },
    {
        name: 'pbkdf2-hmac-sha1',
        files: [ 'src/pbkdf2/pbkdf2-hmac-sha1.js' ],
        depends: [ 'pbkdf2', 'hmac-sha1' ],
        implies: [ 'pbkdf2-hmac-sha1-exports' ]
    },
    {
        name: 'pbkdf2-hmac-sha256',
        files: [ 'src/pbkdf2/pbkdf2-hmac-sha256.js' ],
        depends: [ 'pbkdf2', 'hmac-sha256' ],
        implies: [ 'pbkdf2-hmac-sha256-exports' ]
    },
    {
        name: 'pbkdf2-hmac-sha512',
        files: [ 'src/pbkdf2/pbkdf2-hmac-sha512.js' ],
        depends: [ 'pbkdf2', 'hmac-sha512' ],
        implies: [ 'pbkdf2-hmac-sha512-exports' ]
    },
    {
        name: 'pbkdf2-hmac-sha1-exports',
        files: [ 'src/pbkdf2/exports-pbkdf2-hmac-sha1.js' ],
        depends: [ 'pbkdf2' ]
    },
    {
        name: 'pbkdf2-hmac-sha256-exports',
        files: [ 'src/pbkdf2/exports-pbkdf2-hmac-sha256.js' ],
        depends: [ 'pbkdf2' ]
    },
    {
        name: 'pbkdf2-hmac-sha512-exports',
        files: [ 'src/pbkdf2/exports-pbkdf2-hmac-sha512.js' ],
        depends: [ 'pbkdf2' ]
    },
    {
        name: 'rng',
        files: [ 'src/random/isaac.js', 'src/random/random.js' ],
        depends: [ 'common', 'utils', 'pbkdf2-hmac-sha256' ],
        implies: [ 'rng-exports' ]
    },
    {
        name: 'rng-exports',
        files: [ 'src/random/exports.js' ],
        depends: [ 'rng' ]
    },
    {
        name: 'rng-globals',
        files: [ 'src/random/globals.js' ],
        depends: [ 'rng' ]
    },
    {
        name: 'bn',
        files: [ 'src/bignum/bigint.asm.js', 'src/bignum/bignum.js', 'src/bignum/extgcd.js', 'src/bignum/modulus.js', 'src/bignum/prime.js' ],
        depends: [ 'common', 'rng' ],
        implies: [ 'bn-exports' ]
    },
    {
        name: 'bn-exports',
        files: [ 'src/bignum/exports.js' ],
        depends: [ 'bn' ]
    },
    {
        name: 'rsa',
        files: [ 'src/rsa/rsa.js', 'src/rsa/genkey.js' ],
        depends: [ 'bn', 'rng' ],
        implies: [ 'rsa-keygen-exports' ]
    },
    {
        name: 'rsa-raw',
        files: [ 'src/rsa/raw.js' ],
        depends: [ 'rsa' ],
        implies: [ 'rsa-keygen-exports', 'rsa-raw-exports' ]
    },
    {
        name: 'rsa-pkcs1',
        files: [ 'src/rsa/pkcs1.js' ],
        depends: [ 'rsa' ],
        implies: [ 'rsa-keygen-exports', 'rsa-oaep-sha1-exports', 'rsa-oaep-sha256-exports', 'rsa-oaep-sha512-exports',
                                         'rsa-pss-sha1-exports',  'rsa-pss-sha256-exports',  'rsa-pss-sha512-exports' ]
    },
    {
        name: 'rsa-keygen-exports',
        files: [ 'src/rsa/exports-keygen.js' ],
        depends: [ 'rsa' ]
    },
    {
        name: 'rsa-raw-exports',
        files: [ 'src/rsa/exports-raw.js' ],
        depends: [ 'rsa-raw' ]
    },
    {
        name: 'rsa-oaep-sha1-exports',
        files: [ 'src/rsa/exports-oaep-sha1.js' ],
        depends: [ 'rsa-pkcs1', 'sha1' ]
    },
    {
        name: 'rsa-oaep-sha256-exports',
        files: [ 'src/rsa/exports-oaep-sha256.js' ],
        depends: [ 'rsa-pkcs1', 'sha256' ]
    },
    {
        name: 'rsa-oaep-sha512-exports',
        files: [ 'src/rsa/exports-oaep-sha512.js' ],
        depends: [ 'rsa-pkcs1', 'sha512' ]
    },
    {
        name: 'rsa-pss-sha1-exports',
        files: [ 'src/rsa/exports-pss-sha1.js' ],
        depends: [ 'rsa-pkcs1', 'sha1' ]
    },
    {
        name: 'rsa-pss-sha256-exports',
        files: [ 'src/rsa/exports-pss-sha256.js' ],
        depends: [ 'rsa-pkcs1', 'sha256' ]
    },
    {
        name: 'rsa-pss-sha512-exports',
        files: [ 'src/rsa/exports-pss-sha512.js' ],
        depends: [ 'rsa-pkcs1', 'sha512' ]
    },
];

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

    function sources () {
        // Get the list of modules split by commas
        var includeModules = {};
        ( grunt.option('with') || process.env.WITH || '' ).split(',')
            .map( function ( moduleName ) { return moduleName.trim() } )
            .filter( function ( moduleName ) { return moduleName.length > 0 } )
            .forEach( function ( moduleName ) { includeModules[ moduleName ] = true } );

        // Check for keyword "ALL"
        if ( includeModules.ALL ) {
            includeModules = {};
            modules.forEach( function ( module ) { includeModules[ module.name ] = true } );
        }

        // No modules specified, put defaults here
        if ( Object.keys( includeModules ).length === 0 )
            defaults.forEach( function ( moduleName ) { includeModules[moduleName] = true } );

        // Trace build configuration
        var traceModules = modules.filter( function ( module ) { return includeModules[module.name] } )
                                  .map( function ( module ) { return module.name } );
        grunt.log.writeln( "Building modules: " + traceModules.join(", ") );

        // Recurse into dependancy tree
        function traverseDependancies ( moduleName, includeModules ) {
            if ( includeModules[moduleName] )
                return;

            var result = modules.filter( function ( module ) { return module.name === moduleName } );
            if ( !result || result.length === 0 )
                grunt.fail.fatal( "An unknown module '" + moduleName + "' specified" );

            includeModules[ result[0].name ] = true;

            // Get the deps and call recursively
            var depends = result[0].depends || [];

            depends.forEach( function ( dependsName ) { traverseDependancies( dependsName, includeModules ) } );
        }

        // Loop each of the specified module names
        var deepIncludeModules = {};
        Object.keys(includeModules).forEach( function ( moduleName ) { traverseDependancies( moduleName, deepIncludeModules ) } );

        // Insert implied modules only when theirs dependancies are there
        var impliedModules = {};
        for ( var i = 0; i < modules.length; i++ ) {
            if ( !includeModules[ modules[i].name ] || !modules[i].implies ) continue;
            modules[i].implies.forEach( function ( moduleName ) { impliedModules[moduleName] = true } );
        }
        for ( var i = 0; i < modules.length; i++ ) {
            if ( !modules[i].depends ) continue;
            modules[i].depends.forEach( function ( moduleName ) { if ( !deepIncludeModules[moduleName] ) delete impliedModules[ modules[i].name ] } );
            if ( !impliedModules[ modules[i].name ] ) continue;
            deepIncludeModules[ modules[i].name ] = true;
        }
        Object.keys(impliedModules).forEach( function ( moduleName ) { deepIncludeModules[moduleName] = true } );

        // Hold the array of files as specified by the modules
        var sourceFiles = [];
        for ( var i = 0; i < modules.length; i++ ) {
            if ( !deepIncludeModules[ modules[i].name ] ) continue;
            sourceFiles = sourceFiles.concat(modules[i].files);
        }

//        grunt.log.writeln( "Building files:\n" + sourceFiles.join("\n") );

        grunt.config( 'sources.files', sourceFiles );

        return true;
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
                    'asmcrypto.js': '<%= sources.files %>'
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
                    'asmcrypto.js': '<%= sources.files %>'
                }
            }
        },

        qunit: {
            all: {
                options: {
                    timeout: 60000,
                    urls: [ 'http://localhost:9999/index.html' ]
                }
            }
        },

        'saucelabs-qunit': {
            all: {
                options: {
                    testname: 'asmcrypto.js',
                    urls: [ 'http://localhost:9999/' ],
                    browsers: browsers,
                    build: process.env.TRAVIS_JOB_ID,
                    'max-duration': 600
                }
            }
        },

        connect: {
            all: {
                options: {
                    hostname: 'localhost',
                    port: 9999,
                    base: [ 'test', '.' ],
                    directory: 'test'
                }
            }
        },

        watch: {
            all: {
                files: '<%= sources.files %>',
                tasks: ['sources','uglify:devel']
            }
        },

        clean: [
            'asmcrypto.js',
            'asmcrypto.js.map'
        ]
    });

    grunt.registerTask('sources', sources);
    grunt.registerTask('default', ['sources','uglify:release']);
    grunt.registerTask('devel', ['sources','uglify:devel','connect','watch']);
    grunt.registerTask('test', ['connect','qunit']);
    grunt.registerTask('sauce', ['connect','saucelabs-qunit']);
};
