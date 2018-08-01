import fs from 'fs-extra';
import ts from 'typescript';
import rollup from 'rollup';
import UglifyJS from 'uglify-js';
import UglifyES from 'uglify-es';

(async function() {
  // Delete old
  await fs.remove('dist_es5');
  await fs.remove('dist_es8');

  // Run ts
  const raw_config = await fs.readFile('tsconfig.json', 'utf8');
  const options_es5_raw = JSON.parse(raw_config).compilerOptions;
  options_es5_raw.target = 'es5';
  options_es5_raw.outDir = 'dist_es5';
  const options_es8_raw = JSON.parse(raw_config).compilerOptions;

  const options_es5 = ts.convertCompilerOptionsFromJson(options_es5_raw, '.');
  const options_es8 = ts.convertCompilerOptionsFromJson(options_es8_raw, '.');

  const program_es5 = ts.createProgram(['src/entry-export_all.ts'], options_es5.options);
  const program_es8 = ts.createProgram(['src/entry-export_all.ts'], options_es8.options);
  program_es5.emit();
  program_es8.emit();

  // Copy non-ts resources
  await fs.copy('src/aes/aes.asm.js', 'dist_es5/aes/aes.asm.js');
  await fs.copy('src/aes/aes.asm.d.ts', 'dist_es5/aes/aes.asm.d.ts');
  await fs.copy('src/aes/aes.asm.js', 'dist_es8/aes/aes.asm.js');
  await fs.copy('src/aes/aes.asm.d.ts', 'dist_es8/aes/aes.asm.d.ts');

  await fs.copy('src/bignum/bigint.asm.js', 'dist_es5/bignum/bigint.asm.js');
  await fs.copy('src/bignum/bigint.asm.d.ts', 'dist_es5/bignum/bigint.asm.d.ts');
  await fs.copy('src/bignum/bigint.asm.js', 'dist_es8/bignum/bigint.asm.js');
  await fs.copy('src/bignum/bigint.asm.d.ts', 'dist_es8/bignum/bigint.asm.d.ts');

  await fs.copy('src/hash/sha1/sha1.asm.js', 'dist_es5/hash/sha1/sha1.asm.js');
  await fs.copy('src/hash/sha1/sha1.asm.d.ts', 'dist_es5/hash/sha1/sha1.asm.d.ts');
  await fs.copy('src/hash/sha1/sha1.asm.js', 'dist_es8/hash/sha1/sha1.asm.js');
  await fs.copy('src/hash/sha1/sha1.asm.d.ts', 'dist_es8/hash/sha1/sha1.asm.d.ts');

  await fs.copy('src/hash/sha256/sha256.asm.js', 'dist_es5/hash/sha256/sha256.asm.js');
  await fs.copy('src/hash/sha256/sha256.asm.d.ts', 'dist_es5/hash/sha256/sha256.asm.d.ts');
  await fs.copy('src/hash/sha256/sha256.asm.js', 'dist_es8/hash/sha256/sha256.asm.js');
  await fs.copy('src/hash/sha256/sha256.asm.d.ts', 'dist_es8/hash/sha256/sha256.asm.d.ts');

  await fs.copy('src/hash/sha512/sha512.asm.js', 'dist_es5/hash/sha512/sha512.asm.js');
  await fs.copy('src/hash/sha512/sha512.asm.d.ts', 'dist_es5/hash/sha512/sha512.asm.d.ts');
  await fs.copy('src/hash/sha512/sha512.asm.js', 'dist_es8/hash/sha512/sha512.asm.js');
  await fs.copy('src/hash/sha512/sha512.asm.d.ts', 'dist_es8/hash/sha512/sha512.asm.d.ts');

  const es5bundle = await rollup.rollup({
    input: 'dist_es5/entry-export_all.js',
    onwarn(warning, warn) {
      if (warning.code === 'THIS_IS_UNDEFINED') return;
      warn(warning); // this requires Rollup 0.46
    },
  });

  // Legacy browser export, as a bundle
  await es5bundle.write({
    file: 'asmcrypto.all.es5.js',
    format: 'iife',
    name: 'asmCrypto',
  });

  // Legacy browser export, as a bundle
  await es5bundle.write({
    file: 'asmcrypto.all.es5.mjs',
    format: 'es',
  });

  // NodeJS old
  await es5bundle.write({
    file: 'asmcrypto.all.js',
    format: 'cjs',
  });

  const legacyCode = await fs.readFile('asmcrypto.all.es5.js', 'utf8');
  const { error, code } = UglifyJS.minify(legacyCode, {
    compress: {
      inline: false,
      collapse_vars: false,
      reduce_vars: false,
    },
  });
  if (error) throw new Error(`Uglify failed: ${error}`);
  await fs.writeFile('asmcrypto.all.es5.min.js', code, 'utf8');

  // Modern export, eg. Chrome or NodeJS 10 with ESM
  const es8bundle = await rollup.rollup({
    input: 'dist_es8/entry-export_all.js',
    onwarn(warning, warn) {
      if (warning.code === 'THIS_IS_UNDEFINED') return;
      warn(warning); // this requires Rollup 0.46
    },
  });
  await es8bundle.write({
    file: 'asmcrypto.all.es8.js',
    format: 'es',
  });

  const es8Code = await fs.readFile('asmcrypto.all.es8.js', 'utf8');
  const { error: errorEs8, code: codeEs8 } = UglifyES.minify(es8Code, {
    compress: {
      inline: false,
      collapse_vars: false,
      reduce_vars: false,
    },
  });
  if (errorEs8) throw new Error(`Uglify failed: ${error}`);
  await fs.writeFile('asmcrypto.all.es8.min.js', codeEs8, 'utf8');

  console.log('Build complete');
})();
