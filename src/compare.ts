import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Values are compared as HMAC-SHA256 digests under a random 32-byte key made
 * once per run and held only in this object. A value is reduced the moment it
 * arrives and the plaintext is not kept; digests are compared in constant time
 * and never leave the comparison, so nothing comparable is printed, written or
 * reusable across runs.
 */
export interface Digest {
  exact: Buffer;
  trimmed: Buffer;
}

export class Digester {
  readonly #key = randomBytes(32);

  /**
   * The exact digest decides equality. The second digest, of the value with
   * one trailing newline (\n or \r\n) removed, is used only to say that two
   * different values differ by nothing but that newline.
   */
  digest = (value: string): Digest => ({ exact: this.#mac(value), trimmed: this.#mac(value.replace(/\r?\n$/, '')) });

  #mac(value: string): Buffer {
    return createHmac('sha256', this.#key).update(value, 'utf8').digest();
  }

  static same(a: Buffer, b: Buffer): boolean {
    return a.length === b.length && timingSafeEqual(a, b);
  }

  toJSON(): string {
    return '[Digester]';
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return '[Digester]';
  }
}
