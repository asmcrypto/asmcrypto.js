// Source files list
var src = [
    // 'common'
    'src/errors.js',

    // 'utils'
    'src/utils.js',

    // 'aes' (depends on 'common', 'utils')
    'src/aes/aes.asm.js', 'src/aes/aes.js',

    // 'aes-cbc' (depends on 'aes')
    'src/aes/aes-cbc.js',

    // 'aes-ccm' (depends on 'aes')
    'src/aes/aes-ccm.js',
/*
    // 'aes-cfb' (depends on 'aes', off by default)
    'src/aes/aes-cfb.js',
*/
    // 'exports-aes' (depends on 'aes')
    'src/aes/exports.js',

    // 'sha1' (depends on 'common', 'utils')
    'src/sha1/sha1.asm.js', 'src/sha1/sha1.js',

    // 'exports-sha1' (depends on 'sha1')
    'src/sha1/exports.js',

    // 'sha256' (depends on 'common', 'utils')
    'src/sha256/sha256.asm.js', 'src/sha256/sha256.js',

    // 'exports-sha256' (depends on 'sha256')
    'src/sha256/exports.js',
/*
    // 'sha512' (depends on 'common', 'utils', off by default)
    'src/sha512/sha512.asm.js', 'src/sha512/sha512.js',

    // 'exports-sha256' (depends on 'sha512', off by default)
    'src/sha512/exports.js',
*/
    // 'hmac' (depends on 'common', 'utils')
    'src/hmac/hmac.js',

    // 'hmac-sha1' (depends on 'hmac', 'sha1')
    'src/hmac/hmac-sha1.js',

    // 'hmac-sha256' (depends on 'hmac', 'sha256')
    'src/hmac/hmac-sha256.js',
/*
    // 'hmac-sha512' (depends on 'hmac', 'sha512', off by default)
    'src/hmac/hmac-sha512.js',
*/
    // 'exports-hmac' (depends on 'hmac')
    'src/hmac/exports.js',

    // 'pbkdf2' (depends on 'common', 'utils')
    'src/pbkdf2/pbkdf2.js',

    // 'pbkdf2-hmac-sha1' (depends on 'pbkdf2', 'hmac-sha1')
    'src/pbkdf2/pbkdf2-hmac-sha1.js',

    // 'pbkdf2-hmac-sha256' (depends on 'pbkdf2', 'hmac-sha256')
    'src/pbkdf2/pbkdf2-hmac-sha256.js',
/*
    // 'pbkdf2-hmac-sha512' (depends on 'pbkdf2', 'hmac-sha512', off by default)
    'src/pbkdf2/pbkdf2-hmac-sha512.js',
*/
    // 'exports-pbkdf2' (depends on 'pbkdf2')
    'src/pbkdf2/exports.js',

    // 'rng' (depends on 'common', 'utils')
    'src/random/isaac.js', 'src/random/random.js',

    // 'exports-rng' (depends on 'rng')
    'src/random/exports.js',

    // 'globals-rng' (depends on 'rng')
    'src/random/globals.js',

    // 'bn' (depends on 'common', 'rng')
    'src/bignum/bigint.asm.js', 'src/bignum/bignum.js', 'src/bignum/extgcd.js', 'src/bignum/modulus.js', 'src/bignum/prime.js',

    // 'exports-bn' (depends on 'bn')
    'src/bignum/exports.js',

    // 'rsa' (depends on 'bn', 'rng')
    'src/rsa/rsa.js', 'src/rsa/genkey.js',

    // 'rsa-pkcs1' (depends on 'rsa')
    'src/rsa/pkcs1.js',

    // 'exports-rsa' (depends on 'rsa')
    'src/rsa/exports.js',

    // 'exports' (depends on 'utils')
    'src/exports.js',

    // 'globals' (depends on 'common')
    'src/globals.js'
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
module.exports = function(grunt) {
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-connect');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-saucelabs');

    // Map each of the modules and their deps
    var modules = {
        "common": {
            files: ['errors.js']
        },
        "utils": {
            files: ['utils.js']
        },
        "aes": {
            files: ['aes/aes.asm.js', 'aes/aes.js'],
            depends: ['common', 'utils']
        },
        "aes-cbc": {
            files: ['aes/aes-cbc.js'],
            depends: ['aes']
        },
        "aes-ccm": {
            files: ['aes/aes-ccm.js'],
            depends: ['aes']
        },
        "aes-cfb": {
            files: ['aes/aes-cfb.js'],
            depends: ['aes']
        },
        "exports-aes": {
            files: ['aes/exports.js'],
            depends: ['aes']
        },
        "sha1": {
            files: ['sha1/sha1.asm.js', 'sha1/sha1.js'],
            depends: ['common', 'utils']
        },
        "exports-sha1": {
            files: ['sha1/exports.js'],
            depends: ['sha1']
        },
        "sha256": {
            files: ['sha256/sha256.asm.js', 'sha256/sha256.js'],
            depends: ['common', 'utils']
        },
        "exports-sha256": {
            files: ['sha256/exports.js'],
            depends: 'sha256'
        },
        "sha512": {
            files: ['sha512/sha512.asm.js', 'sha512/sha512.js'],
            depends: ['common', 'utils']
        },
        "exports-sha512": {
            files: ['sha512/exports.js'],
            depends: ['sha512']
        },
        "hmac": {
            files: ['hmac/hmac.js'],
            depends: ['common', 'utils']
        },
        "hmac-sha1": {
            files: ['hmac/hmac-sha1.js'],
            depends: ['hmac', 'sha1']
        },
        "hmac-sha256": {
            files: ['hmac/hmac-sha256.js'],
            depends: ['hmac', 'sha256']
        },
        "hmac-sha512": {
            files: ['hmac/hmac-sha512.js'],
            depends: ['hmac', 'sha512']
        },
        "exports-hmac": {
            files: ['hmac/exports.js'],
            depends: ['hmac']
        },
        "pbkdf2": {
            files: ['pbkdf2/pbkdf2.js'],
            depends: ['common', 'utils']
        },
        "pbkdf2-hmac-sha1": {
            files: ['pbkdf2/pbkdf2-hmac-sha1.js'],
            depends: ['pbkdf2', 'hmac-sha1']
        },
        "pbkdf2-hmac-sha1": {
            files: ['pbkdf2/pbkdf2-hmac-sha256.js'],
            depends: ['pbkdf2', 'hmac-sha256']
        },
        "pbkdf2-hmac-sha1": {
            files: ['pbkdf2/pbkdf2-hmac-sha512.js'],
            depends: ['pbkdf2', 'hmac-sha512']
        },
        "exports-pbkdf2": {
            files: ['pbkdf2/exports.js'],
            depends: ['pbkdf2']
        },
        "rng": {
            files: ['random/isaac.js', 'random/random.js'],
            depends: ['common', 'utils']
        },
        "exports-rng": {
            files: ['random/exports.js'],
            depends: ['rng']
        },
        "globals-rng": {
            files: ['random/globals.js'],
            depends: ['rng']
        },
        "bn": {
            files: ['bignum/bigint.asm.js', 'bignum/bignum.js', 'bignum/extgcd.js', 'bignum/modulus.js', 'bignum/prime.js'],
            depends: ['common', 'rng']
        },
        "exports-bn": {
            files: ['bignum/exports.js'],
            depends: ['bn']
        },
        "rsa": {
            files: ['rsa/rsa.js', 'rsa/genkey.js'],
            depends: ['bn', 'rng']
        },
        "rsa-pkcs1": {
            files: ['rsa/pkcs1.js'],
            depends: ['rsa']
        },
        "exports-rsa": {
            files: ['rsa/exports.js'],
            depends: ['rsa']
        },
        "exports": {
            files: ['exports.js'],
            depends: ['utils']
        },
        "globals": {
            files: ['globals.js'],
            depends: ['common']
        }
    }

    // Get the list of modules split by commas
    var includedModules = (grunt.option('with') || '').split(',');

    // No modules specified, put defaults here
    if (includedModules.length === 0) {
        includedModules = [];
    }

    // Hold the array of files as specified by the modules
    var src = [];

    // Gets the paths (including any deps) for a module
    function getPathsForModule(moduleName) {
        // Get the module (trim any spaces too)
        var module = modules[moduleName.trim()];
        // If the module doesn't exist, fail
        if (!module) {
            grunt.fail.fatal('An unknown module was specified');
        }
        // The final paths that are found for the module and all deps
        var paths = [];
        // Get the deps and call recursively
        (module.depends || []).forEach(function(moduleName) {
            paths = paths.concat(
                getPathsForModule(moduleName)
            );
        });
        // Return the paths for the deps plus the files from the module
        return paths.concat(module.files);
    }

    // Loop each of the specified module names
    includedModules.forEach(function(moduleName) {
        // Add the paths to src 
        src = src.concat(
            getPathsForModule(
                moduleName.trim()
            )
        );
    });

    // Prepend each value of src with 'src/' and filter the duplicate files (included multiple times)
    src = src.map(function(path) {
        return 'src/' + path;
    }).filter(function(elem, pos, self) {
        return self.indexOf(elem) == pos;
    });

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
                    testname: "asmcrypto.js",
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
