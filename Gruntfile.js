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
                files: {
                    'asmcrypto.js': [
                        'src/utils.js',
                        'src/core/errors.js',
                        'src/core/aes.asm.js', 'src/core/aes.js', 'src/core/aes-cbc.js', 'src/core/aes-ccm.js',
                        'src/core/sha256.asm.js', 'src/core/sha256.js',
                        'src/core/hmac.js',
                        'src/core/pbkdf2.js',
                        'src/core/api.js'
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
