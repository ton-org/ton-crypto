/**
 * Copyright (c) Whales Corp. 
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import jsSHA from 'jssha';
import { sha256 as internal } from '@ton/crypto-primitives';

export function sha256_sync(source: Buffer | string): Buffer {
    let src: Buffer;
    if (typeof source === 'string') {
        src = Buffer.from(source, 'utf-8');
    } else {
        src = source;
    }

    let hasher = new jsSHA('SHA-256', 'UINT8ARRAY');
    hasher.update(src);
    let res = hasher.getHash('UINT8ARRAY');
    return Buffer.from(res.buffer, res.byteOffset, res.byteLength);
}

export async function sha256_fallback(source: Buffer | string): Promise<Buffer> {
    return sha256_sync(source);
}

export function sha256(source: Buffer | string): Promise<Buffer> {
    return internal(source);
}