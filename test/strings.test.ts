import { describe, it, expect } from 'vitest';
import { extractStrings } from '../src/core/strings.js';

describe('extractStrings', () => {
  it('extracts ASCII runs at or above minLength', () => {
    const buffer = Buffer.concat([
      Buffer.from('hello world', 'latin1'),
      Buffer.from([0x00, 0x01, 0x02]),
      Buffer.from('abc', 'latin1'), // 3 chars: below min
      Buffer.from([0xff]),
      Buffer.from('PE\x00\x00\x00 and more text', 'latin1')
    ]);
    const strings = extractStrings(buffer, { minLength: 4 });
    const texts = strings.filter((s) => s.encoding === 'ascii').map((s) => s.text);
    expect(texts).toContain('hello world');
    expect(texts).toContain(' and more text');
    expect(texts).not.toContain('abc');
  });

  it('extracts UTF-16LE runs', () => {
    const utf16 = Buffer.from('secret', 'utf16le'); // printable + 0x00 pairs
    const terminator = Buffer.from([0xff, 0xff]);
    const buffer = Buffer.concat([Buffer.alloc(8, 0x00), utf16, terminator]);
    const strings = extractStrings(buffer, { minLength: 4 });
    const found = strings.find(
      (s) => s.encoding === 'utf16le' && s.text === 'secret'
    );
    expect(found).toBeDefined();
    expect(found!.offset).toBe(8);
  });

  it('respects a raised minLength', () => {
    // Two 8-char runs separated by a NUL byte.
    const buffer = Buffer.concat([
      Buffer.from('abcdefgh', 'latin1'),
      Buffer.from([0x00]),
      Buffer.from('12345678', 'latin1')
    ]);
    const four = extractStrings(buffer, { minLength: 4 });
    const eight = extractStrings(buffer, { minLength: 8 });
    const nine = extractStrings(buffer, { minLength: 9 });
    expect(four).toHaveLength(2);
    expect(eight).toHaveLength(2);
    expect(nine).toHaveLength(0);
  });

  it('caps output at maxStrings', () => {
    // 50 separated 8-char runs; cap at 10.
    const unit = Buffer.concat([Buffer.from('aaaaaaaa', 'latin1'), Buffer.from([0x00])]);
    const buffer = Buffer.concat(Array(50).fill(unit));
    const strings = extractStrings(buffer, { minLength: 4, maxStrings: 10 });
    expect(strings.length).toBe(10);
  });

  it('returns nothing for an empty buffer', () => {
    expect(extractStrings(Buffer.alloc(0))).toHaveLength(0);
  });
});
