module.exports = function(grunt) {
    grunt.loadNpmTasks('grunt-feature');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    grunt.loadNpmTasks('grunt-contrib-clean');

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        uglify: {
            all: {
                options: {
                    mangle: true,
                    compress: true,
                    beautify: false,
                    sourceMap: 'asmcrypto.js.map',
                    wrap: 'asmCrypto'
                },
/*
                options: {
                    mangle: false,
                    compress: false,
                    beautify: true,
                    sourceMap: 'asmcrypto.js.map',
                    wrap: 'asmCrypto'
                },
*/
                files: {
                    'asmcrypto.js': [
                        'src/utils.js',
                        'src/errors.js',

                        'src/aes/aes.asm.js', 'src/aes/aes.js', 'src/aes/aes-cbc.js', 'src/aes/aes-ccm.js', 'src/aes/aes-cfb.js', 'src/aes/exports.js',

                        'src/sha1/sha1.asm.js', 'src/sha1/sha1.js', 'src/sha1/exports.js',

                        'src/sha256/sha256.asm.js', 'src/sha256/sha256.js', 'src/sha256/exports.js',

                        'src/sha512/sha512.asm.js', 'src/sha512/sha512.js', 'src/sha512/exports.js',

                        'src/hmac/hmac.js', 'src/hmac/hmac-sha1.js', 'src/hmac/hmac-sha256.js', 'src/hmac/hmac-sha512.js', 'src/hmac/exports.js',

                        'src/pbkdf2/pbkdf2.js', 'src/pbkdf2/pbkdf2-hmac-sha1.js', 'src/pbkdf2/pbkdf2-hmac-sha256.js', 'src/pbkdf2/pbkdf2-hmac-sha512.js', 'src/pbkdf2/exports.js',

                        'src/random/isaac.js', 'src/random/random.js', 'src/random/exports.js',

                        'src/bignum/bigint.asm.js', 'src/bignum/bignum.js', 'src/bignum/extgcd.js', 'src/bignum/modulus.js', 'src/bignum/prime.js', 'src/bignum/exports.js',

                        'src/rsa/rsa.js', 'src/rsa/genkey.js', 'src/rsa/pkcs1.js', 'src/rsa/exports.js',

                        'src/exports.js', 'src/globals.js'
                    ]
                }
            }
        },

        qunit: {
            all: ['test.html']
        },

        clean: [
            'asmcrypto.js',
            'asmcrypto.js.map'
        ]
    });

    grunt.registerTask('default', ['uglify']);
    grunt.registerTask('test', ['qunit']);
};
