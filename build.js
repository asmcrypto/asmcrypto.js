import * as fs from 'fs-extra';
import ts from 'typescript';
import * as rollup from 'rollup';
import { terser } from "rollup-plugin-terser";

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
  const result_es5 = program_es5.emit();
  if (result_es5.emitSkipped) {
    throw new Error(result_es5.diagnostics[0].messageText);
  }
  const result_es8 = program_es8.emit();
  if (result_es8.emitSkipped) {
    throw new Error(result_es8.diagnostics[0].messageText);
  }

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

  let makeBundle = (input, min) => {
    let config = {
      input: input,
      onwarn(warning, warn) {
        if (warning.code === 'THIS_IS_UNDEFINED') return;
        warn(warning); // this requires Rollup 0.46
      },
    }
    if (min) {
      config.plugins = [terser({
        numWorkers: 4
      })]
    }
    return rollup.rollup(config);
  }

  const es5bundle = await makeBundle('dist_es5/entry-export_all.js')
  const es8bundle = await makeBundle('dist_es8/entry-export_all.js')
  const es5bundleMin = await makeBundle('dist_es5/entry-export_all.js', true)
  const es8bundleMin = await makeBundle('dist_es8/entry-export_all.js', true)

  let buildAll = async (es5bundle, es8bundle, configWrap) => {
    // Legacy browser export, as a bundle
    await es5bundle.write(configWrap({
      file: 'asmcrypto.all.es5.js',
      format: 'iife',
      name: 'asmCrypto',
    }));

    // Legacy browser export, as a bundle
    await es5bundle.write(configWrap({
      file: 'asmcrypto.all.es5.mjs',
      format: 'es',
    }));

    // NodeJS old
    await es5bundle.write(configWrap({
      file: 'asmcrypto.all.js',
      format: 'cjs',
    }));

    // Modern export, eg. Chrome or NodeJS 10 with ESM
    await es8bundle.write(configWrap({
      file: 'asmcrypto.all.es8.js',
      format: 'es',
    }));
  }

  let minifyConfigWrap = (c) => {
    let fn = c.file;
    if (fn.endsWith('.js')) c.file = fn.slice(0, -3) + '.min.js';
    if (fn.endsWith('.mjs')) c.file = fn.slice(0, -4) + '.min.mjs';
    c.sourcemap = true;
    return c;
  }

  await buildAll(es5bundle, es8bundle, (c) => c);
  await buildAll(es5bundleMin, es8bundleMin, minifyConfigWrap)
  console.log('Build complete');
})();
