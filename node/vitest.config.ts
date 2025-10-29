import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      reporter: ['text', 'lcov'],
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    },
    reporters: ['default'],
    globals: true
  }
});
