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
