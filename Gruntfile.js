// Grunt setup
module.exports = function (grunt) {
  grunt.loadNpmTasks('grunt-contrib-uglify-es');
  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-connect');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-jsdoc');
  grunt.loadNpmTasks('grunt-rollup');
  grunt.loadNpmTasks('grunt-shell');

  // Finally, configure
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    rollup: {
      options: {
        format: 'umd',
        sourceMap: true,
        banner: "/*! asmCrypto<%= pkg.version && ' v'+pkg.version %>, (c) 2018 <%= pkg.author.name %>, opensource.org/licenses/<%= pkg.license %> */",
      },
      default: {
        options: {
          moduleName: 'asmCrypto',
        },
        files: {
          'asmcrypto.js': './src/entry-default.js',
        },
      },
      all: {
        options: {
          moduleName: 'asmCrypto',
        },
        files: {
          'asmcrypto.all.js': './src/entry-export_all.js',
        },
      },
      all_esm: {
        options: {
          format: 'es',
        },
        files: {
          'asmcrypto.mjs': './src/entry-export_all.js',
        },
      },
      test_AES_ASM: {
        options: {
          moduleName: 'AES_asm',
        },
        files: {
          'test/aes.asm.js': './src/aes/aes.asm.js',
        },
      },
    },

    shell: {
      test: {
        command: '"./node_modules/.bin/qunit-puppeteer" http://localhost:9999/index.html'
      }
    },

    uglify: {
      options: {
        mangle: {},
        compress: {},
        sourceMap: true,
        sourceMapIn: 'asmcrypto.js.map',
        sourceMapIncludeSources: true,
        screwIE8: true,
        banner: "/*! asmCrypto<%= pkg.version && ' v'+pkg.version %>, (c) 2018 <%= pkg.author.name %>, opensource.org/licenses/<%= pkg.license %> */",
      },
      all: {
        files: {
          'asmcrypto.min.js': 'asmcrypto.js',
        },
      },
    },

    jsdoc: {
      all: {
        src: ['src/**/*.js', 'README.md'],
        options: {
          destination: 'doc',
        },
      },
    },

    connect: {
      all: {
        options: {
          hostname: 'localhost',
          port: 9999,
          base: ['test', '.'],
          directory: 'test',
        },
      },
    },

    watch: {
      all: {
        files: 'src/**/*.js',
        tasks: ['rollup:all', 'rollup:test_AES_ASM'],
      },
    },

    clean: [
      'asmcrypto.js',
      'asmcrypto.js.map',
      'test/aes.asm.js',
      'test/aes.asm.js.map',
      'doc/',
    ],
  });

  grunt.registerTask('default', ['rollup:default', 'rollup:test_AES_ASM', 'uglify']);
  grunt.registerTask('all', ['rollup:all']);
  grunt.registerTask('esm', ['rollup:all_esm']);
  grunt.registerTask('devel', ['rollup:all', 'rollup:test_AES_ASM', 'connect', 'watch']);
  grunt.registerTask('test', ['connect', 'shell']);
};
