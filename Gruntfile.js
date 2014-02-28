module.exports = function(grunt) {
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        uglify: {
            core: {
                options: {
                    mangle: false,
                    compress: false,
                    beautify: true,
                    sourceMap: 'asmcrypto.js.map',
                    wrap: 'asmCrypto'
                },
                files: {
                    'asmcrypto.js': [
                        'src/utils.js',
                        'src/core/errors.js',
                        'src/core/aes.asm.js', 'src/core/aes.js', 'src/core/aes-cbc.js', 'src/core/aes-ccm.js',
                        'src/core/sha256.asm.js', 'src/core/sha256.js',
                        'src/core/hmac.js',
                        'src/core/pbkdf2.js',
                        'src/core/api.js',
                        'src/bignum/bigint.asm.js', 'src/bignum/bignum.js', 'src/bignum/extgcd.js', 'src/bignum/modulus.js', 'src/bignum/api.js',
                        'src/rsa/rsa.js', 'src/rsa/genkey.js', 'src/rsa/api.js',
                    ]
                }
            }
        },

        clean: [
            'asmcrypto.js',
            'asmcrypto.js.map'
        ]
    });

    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-clean');

    grunt.registerTask('default', ['uglify:core']);
};
