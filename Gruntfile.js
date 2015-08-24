// Default modules to build
var defaults = [
    'utils',
    'globals',
    'aes-cbc',
    'aes-gcm',
    'sha1',
    'sha256',
    'hmac-sha1',
    'hmac-sha256',
    'pbkdf2-hmac-sha1',
    'pbkdf2-hmac-sha256',
    'rng',
    'bn',
    'rsa-pkcs1',
    'rng-globals',
    'origin',
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
        name: 'origin',
        files: [ 'src/origin.js' ],
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
        files: [ 'src/aes/ecb/ecb.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-ecb-exports' ]
    },
    {
        name: 'aes-cbc',
        files: [ 'src/aes/cbc/cbc.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-cbc-exports' ]
    },
    {
        name: 'aes-cfb',
        files: [ 'src/aes/cfb/cfb.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-cfb-exports' ]
    },
    {
        name: 'aes-ofb',
        files: [ 'src/aes/ofb/ofb.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-ofb-exports' ]
    },
    {
        name: 'aes-ctr',
        files: [ 'src/aes/ctr/ctr.js' ],
        depends: [ 'aes' ],
        implies: [ 'aes-exports', 'aes-ctr-exports' ]
    },
    {
        name: 'aes-ccm',
        files: [ 'src/aes/ccm/ccm.js' ],
        depends: [ 'aes', 'aes-ctr' ],
        implies: [ 'aes-exports', 'aes-ccm-exports' ]
    },
    {
        name: 'aes-gcm',
        files: [ 'src/aes/gcm/gcm.js' ],
        depends: [ 'aes', 'aes-ctr' ],
        implies: [ 'aes-exports', 'aes-gcm-exports' ]
    },
    {
        name: 'aes-exports',
        files: [ 'src/aes/exports.js' ],
        depends: [ 'aes' ]
    },
    {
        name: 'aes-ecb-exports',
        files: [ 'src/aes/ecb/exports.js' ],
        depends: [ 'aes-ecb', 'aes-exports' ]
    },
    {
        name: 'aes-cbc-exports',
        files: [ 'src/aes/cbc/exports.js' ],
        depends: [ 'aes-cbc', 'aes-exports' ]
    },
    {
        name: 'aes-cfb-exports',
        files: [ 'src/aes/cfb/exports.js' ],
        depends: [ 'aes-cfb', 'aes-exports' ]
    },
    {
        name: 'aes-ofb-exports',
        files: [ 'src/aes/ofb/exports.js' ],
        depends: [ 'aes-ofb', 'aes-exports' ]
    },
    {
        name: 'aes-ctr-exports',
        files: [ 'src/aes/ctr/exports.js' ],
        depends: [ 'aes-ctr', 'aes-exports' ]
    },
    {
        name: 'aes-ccm-exports',
        files: [ 'src/aes/ccm/exports.js' ],
        depends: [ 'aes-ccm', 'aes-exports' ]
    },
    {
        name: 'aes-gcm-exports',
        files: [ 'src/aes/gcm/exports.js' ],
        depends: [ 'aes-gcm', 'aes-exports' ]
    },
    {
        name: 'hash',
        files: [ 'src/hash/hash.js' ],
        depends: [ 'common', 'utils' ]
    },
    {
        name: 'sha1',
        files: [ 'src/hash/sha1/sha1.asm.js', 'src/hash/sha1/sha1.js' ],
        depends: [ 'common', 'hash', 'utils' ],
        implies: [ 'sha1-exports' ]
    },
    {
        name: 'sha1-exports',
        files: [ 'src/hash/sha1/exports.js' ],
        depends: [ 'sha1' ]
    },
    {
        name: 'sha256',
        files: [ 'src/hash/sha256/sha256.asm.js', 'src/hash/sha256/sha256.js' ],
        depends: [ 'common', 'hash', 'utils' ],
        implies: [ 'sha256-exports' ]
    },
    {
        name: 'sha256-exports',
        files: [ 'src/hash/sha256/exports.js' ],
        depends: [ 'sha256' ],
    },
    {
        name: 'sha512',
        files: [ 'src/hash/sha512/sha512.asm.js', 'src/hash/sha512/sha512.js' ],
        depends: [ 'common', 'hash', 'utils' ],
        implies: [ 'sha512-exports' ]
    },
    {
        name: 'sha512-exports',
        files: [ 'src/hash/sha512/exports.js' ],
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
    }
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
        browserName: 'Safari',
        platform: 'OS X 10.11',
    },
    // Legacy browsers
    {
        browserName: 'Firefox',
        version: '22',
    },
    {
        browserName: 'Internet Explorer',
        version: '10',
    },
    {
        browserName: 'Opera',
        version: '12',
    },
    {
        browserName: 'Safari',
        version: '5.1',
    },
];

// Grunt setup
module.exports = function ( grunt ) {
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-connect');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-saucelabs');
    grunt.loadNpmTasks('grunt-jsdoc');

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

        concat: {
            options: {
                banner: "/*! asmCrypto<%= pkg.version && ' v'+pkg.version %>, (c) 2013 <%= pkg.author.name %>, opensource.org/licenses/<%= pkg.license %> */\n"
                      + "!function ( exports, global ) {\n\n",
                footer: "\nglobal.asmCrypto=exports;\n}( {}, function(){return this}() );",
                sourceMap: true,
                sourceMapStyle: 'link'
            },
            devel: {
                files: {
                    'asmcrypto.js': '<%= sources.files %>'
                }
            }
        },

        uglify: {
            options: {
                mangle: {},
                compress: {},
                wrap: 'asmCrypto',
                sourceMap: true,
                sourceMapIncludeSources: true,
                screwIE8: true,
                banner: "/*! asmCrypto<%= pkg.version && ' v'+pkg.version %>, (c) 2013 <%= pkg.author.name %>, opensource.org/licenses/<%= pkg.license %> */"
            },
            release: {
                files: {
                    'asmcrypto.js': '<%= sources.files %>'
                }
            }
        },

        jsdoc: {
            all: {
                src: [ 'src/**/*.js', 'README.md' ],
                options: {
                    destination: 'doc'
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
                tasks: ['sources','concat']
            }
        },

        clean: [
            'asmcrypto.js',
            'asmcrypto.js.map',
            'doc/'
        ]
    });

    grunt.registerTask('sources', sources);
    grunt.registerTask('default', ['sources','uglify']);
    grunt.registerTask('devel', ['sources','concat','connect','watch']);
    grunt.registerTask('test', ['connect','qunit']);
    grunt.registerTask('sauce', ['connect','saucelabs-qunit']);
};
