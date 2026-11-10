/**
 * Operational error thrown for user-facing failures (bad path, file too
 * large, malformed input). The CLI maps these to exit code 2.
 */
export class FindcryptError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'FindcryptError';
    this.code = code;
  }
}
