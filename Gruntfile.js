module.exports = function(grunt) {
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        uglify: {
            asmcrypto: {
                options: {
                    mangle: true,
                    compress: true,
                    sourceMap: 'asmcrypto.js.map',
                    wrap: 'asmCrypto'
                },
                files: {
                    'asmcrypto.js': [
                        'src/helpers.js',
                        'src/aes.asm.js', 'src/aes.js',
                        'src/sha256.asm.js', 'src/sha256.js',
                        'src/hmac.js',
                        'src/pbkdf2.js'
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

    grunt.registerTask('default', ['uglify']);
};
