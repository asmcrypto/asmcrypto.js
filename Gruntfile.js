module.exports = function(grunt) {
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        uglify: {
            core: {
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
                        'src/core/errors.js',
                        'src/core/aes.asm.js', 'src/core/aes.js', 'src/core/aes-cbc.js', 'src/core/aes-ccm.js', 'src/core/aes-cfb.js',
                        'src/core/sha256.asm.js', 'src/core/sha256.js', 'src/core/sha512.asm.js', 'src/core/sha512.js',
                        'src/core/hmac.js',
                        'src/core/pbkdf2.js',
                        'src/core/api.js',
                        'src/random/isaac.js', 'src/random/random.js', 'src/random/api.js',
                        'src/bignum/bigint.asm.js', 'src/bignum/bignum.js', 'src/bignum/extgcd.js', 'src/bignum/modulus.js', 'src/bignum/prime.js', 'src/bignum/api.js',
                        'src/rsa/rsa.js', 'src/rsa/genkey.js', 'src/rsa/pkcs1.js', 'src/rsa/api.js',
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

    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    grunt.loadNpmTasks('grunt-contrib-clean');

    grunt.registerTask('default', ['uglify:core']);
    grunt.registerTask('test', ['qunit']);
};
