import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Values are compared as HMAC-SHA256 digests under a random 32-byte key made
 * once per run and held only in this object. A value is reduced the moment it
 * arrives and the plaintext is not kept; digests are compared in constant time
 * and never leave the comparison, so nothing comparable is printed, written or
 * reusable across runs.
 */
export class Digester {
  readonly #key = randomBytes(32);

  digest = (value: string): Buffer => createHmac('sha256', this.#key).update(value, 'utf8').digest();

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
