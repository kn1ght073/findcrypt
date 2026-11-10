import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'cli/main': 'src/cli/main.ts'
  },
  format: ['esm', 'cjs'],
  target: 'node18',
  platform: 'node',
  dts: 'src/index.ts',
  clean: true,
  sourcemap: false,
  treeshake: false
});
