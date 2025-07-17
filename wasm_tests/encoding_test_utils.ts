/**
 * Utilities for testing and debugging encoding issues in WASM
 */

/**
 * Check if a Uint8Array contains valid UTF-8 text
 */
export function isValidUtf8(data: Uint8Array): boolean {
    try {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        decoder.decode(data);
        return true;
    } catch {
        return false;
    }
}

/**
 * Check if data looks like base64
 */
export function isLikelyBase64(data: Uint8Array): boolean {
    if (data.length === 0) return false;
    
    // Try to decode as string first
    if (!isValidUtf8(data)) return false;
    
    const str = new TextDecoder().decode(data);
    // Base64 regex with optional whitespace
    return /^[A-Za-z0-9+/\s]*={0,2}$/.test(str) && (str.length % 4 === 0 || str.length < 4);
}

/**
 * Check if data is likely binary (has non-printable characters)
 */
export function isLikelyBinary(data: Uint8Array): boolean {
    let nonPrintableCount = 0;
    
    for (const byte of data) {
        // Count non-printable, non-whitespace characters
        if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
            nonPrintableCount++;
        }
    }
    
    // If more than 10% non-printable, it's likely binary
    return (nonPrintableCount * 10) > data.length;
}

/**
 * Debug helper to log data format
 */
export function logDataFormat(name: string, data: Uint8Array): void {
    console.log(`\n=== Data Format Analysis: ${name} ===`);
    console.log(`Length: ${data.length} bytes`);
    console.log(`Is valid UTF-8: ${isValidUtf8(data)}`);
    console.log(`Is likely Base64: ${isLikelyBase64(data)}`);
    console.log(`Is likely Binary: ${isLikelyBinary(data)}`);
    
    // Show preview
    if (data.length > 0) {
        const hexPreview = Array.from(data.slice(0, 16))
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
        console.log(`Hex preview: ${hexPreview}${data.length > 16 ? '...' : ''}`);
        
        if (isValidUtf8(data) && !isLikelyBinary(data)) {
            const textPreview = new TextDecoder().decode(data.slice(0, 50));
            console.log(`Text preview: "${textPreview}${data.length > 50 ? '...' : ''}"`);
        }
    }
    console.log('===================================\n');
}

/**
 * Assert that data is in expected format
 */
export function assertDataFormat(
    data: Uint8Array, 
    expectedFormat: 'binary' | 'base64' | 'utf8',
    context: string = ''
): void {
    const prefix = context ? `[${context}] ` : '';
    
    switch (expectedFormat) {
        case 'binary':
            if (!isLikelyBinary(data) && isLikelyBase64(data)) {
                throw new Error(`${prefix}Expected binary data but got base64`);
            }
            break;
            
        case 'base64':
            if (!isLikelyBase64(data)) {
                throw new Error(`${prefix}Expected base64 data but got ${isLikelyBinary(data) ? 'binary' : 'other'}`);
            }
            break;
            
        case 'utf8':
            if (!isValidUtf8(data)) {
                throw new Error(`${prefix}Expected valid UTF-8 but got invalid data`);
            }
            if (isLikelyBinary(data)) {
                throw new Error(`${prefix}Expected UTF-8 text but got binary data`);
            }
            break;
    }
}

/**
 * Convert between formats with validation
 */
export function ensureBinaryFormat(data: Uint8Array, currentFormat?: 'binary' | 'base64'): Uint8Array {
    // Auto-detect if not specified
    if (!currentFormat) {
        if (isLikelyBase64(data)) {
            currentFormat = 'base64';
        } else {
            currentFormat = 'binary';
        }
    }
    
    if (currentFormat === 'base64') {
        const str = new TextDecoder().decode(data);
        const binaryStr = atob(str);
        const binary = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            binary[i] = binaryStr.charCodeAt(i);
        }
        return binary;
    }
    
    return data;
}

export function ensureBase64Format(data: Uint8Array, currentFormat?: 'binary' | 'base64'): Uint8Array {
    // Auto-detect if not specified
    if (!currentFormat) {
        if (isLikelyBase64(data)) {
            currentFormat = 'base64';
        } else {
            currentFormat = 'binary';
        }
    }
    
    if (currentFormat === 'binary') {
        const base64 = btoa(String.fromCharCode(...data));
        return new TextEncoder().encode(base64);
    }
    
    return data;
}