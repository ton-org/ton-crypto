/**
 * Copyright (c) Whales Corp. 
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */


import { sha256, sha256_fallback, sha256_sync } from "./sha256";
import { getSecureRandomBytes } from "./getSecureRandom";

// Test Vectors
// https://www.di-mgt.com.au/sha_testvectors.html
const VECTORS = [
    { value: 'abc', output: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
    { value: '', output: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { value: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', output: '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1' },
    { value: 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu', output: 'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1' }
]

describe('sha256', () => {
    it('should process test vectors', async () => {
        for (let vec of VECTORS) {
            let expected = Buffer.from(vec.output, 'hex');
            let res = await sha256(vec.value);
            expect(res).toEqual(expected);
            res = await sha256(Buffer.from(vec.value, 'utf-8'));
            expect(res).toEqual(expected);
        }
    });

    it('should process test vectors for fallback', async () => {
        for (let vec of VECTORS) {
            let expected = Buffer.from(vec.output, 'hex');
            let res = await sha256_fallback(vec.value);
            expect(res).toEqual(expected);
            res = await sha256_fallback(Buffer.from(vec.value, 'utf-8'));
            expect(res).toEqual(expected);
        }
    });

    it('should process test vectors synchronously', () => {
        for (let vec of VECTORS) {
            let expected = Buffer.from(vec.output, 'hex');
            expect(sha256_sync(vec.value)).toEqual(expected);
            expect(sha256_sync(Buffer.from(vec.value, 'utf-8'))).toEqual(expected);
        }
    });

    it('should match async sha256 on random input', async () => {
        for (let i = 0; i < 64; i++) {
            let length = (await getSecureRandomBytes(2)).readUInt16BE(0) % 300;
            let data = await getSecureRandomBytes(length);
            expect(sha256_sync(data)).toEqual(await sha256(data));
        }
    });
});
