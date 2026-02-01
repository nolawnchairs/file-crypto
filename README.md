# @nolawnchairs/file-crypto

A high-performance Node.js streaming file encryption library using AES-256-GCM with constant-memory operation for large files (1GB+).

> Note this is an in-house library and is not intended for public use. Use at your own risk.

## Features

- **AES-256-GCM encryption** with authenticated encryption (AEAD)
- **Constant-memory streaming** - handles 1GB+ files without buffering
- **File-based API** - simple path-based interface
- **Checksum calculation** - supports multiple hash algorithms
- **Configurable performance** - adjustable buffer sizes
- **TypeScript support** - full type definitions included

## Installation

```bash
npm install @nolawnchairs/file-crypto
```

## Quick Start

```typescript
import { FileCrypto } from '@nolawnchairs/file-crypto'
import { join } from 'node:path'
import { ENCRYPTION_KEY } from 'some-secret-location'

// Create a crypto context with your encryption key
const context = FileCrypto.createContext(ENCRYPTION_KEY)

// Encrypt a file
const encryptor = context.newEncryptor('source.bin', 'encrypted.dat')
await encryptor.write()

// Decrypt a file
const decryptor = context.newDecryptor('encrypted.dat', 'decrypted.bin')
await decryptor.write()
```

## API Documentation

### `FileCrypto.createContext(key, options?)`

Creates a new encryption/decryption context with the provided key.

**Parameters:**
- `key: string` - The encryption key (must be at least 32 bytes in UTF-8 encoding by default)
- `options?: CryptoContextOptions` - Optional configuration (see [Options](#CryptoContextOptions) below)

**Returns:** `CryptoContext`

**Example:**
```typescript
const context = FileCrypto.createContext(ENCRYPTION_KEY, {
  minKeyBytes: 64,
  highWaterMark: 2 * 1024 * 1024 // 2MB buffer
})
```

### `CryptoContextOptions`

Configuration options for creating a crypto context.

```typescript
type CryptoContextOptions = {
  minKeyBytes?: number
  highWaterMark?: number
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `minKeyBytes` | `number` | `32` | Minimum required key length in UTF-8 bytes. The key derivation will enforce this minimum. |
| `highWaterMark` | `number` | `1048576` (1MB) | Stream buffer size in bytes. Larger values improve throughput for large files but use more memory. |

### `CryptoContext`

The encryption context created from a key. Used to create encryptors and decryptors.

#### `context.newEncryptor(sourcePath, targetPath)`

Creates an encryptor for the specified files.

**Parameters:**
- `sourcePath: string` - Path to the source file to encrypt
- `targetPath: string` - Path to the output encrypted file

**Returns:** `FileEncrypt`

#### `context.newDecryptor(sourcePath, targetPath)`

Creates a decryptor for the specified files.

**Parameters:**
- `sourcePath: string` - Path to the encrypted file to decrypt
- `targetPath: string` - Path to the output decrypted file

**Returns:** `FileDecrypt`

### `FileEncrypt`

Encryptor instance for encrypting files.

#### `encryptor.write()`

Encrypts the source file and writes the encrypted data to the target file.

**Returns:** `Promise<void>`

**File Format:**
The encrypted file has the format: `[12-byte nonce][ciphertext][16-byte auth tag]`

### `FileDecrypt`

Decryptor instance for decrypting files.

#### `decryptor.write()`

Decrypts the encrypted file and writes the decrypted data to the target file.

**Returns:** `Promise<void>`

**Note:** Decryption uses constant-memory streaming by reading the nonce from the start and auth tag from the end of the file, making it safe for very large files.

### `FileCrypto.calculateChecksum(source, algorithm, options?)`

Calculates a checksum/hash of a file or stream.

**Parameters:**
- `source: Readable | string` - File path or readable stream
- `algorithm: HashAlgorithm` - Hash algorithm to use (see [Hash Algorithms](#hash-algorithms) below)
- `options?: HashOptions` - Optional Node.js crypto hash options

**Returns:** `Promise<Digester>`

**Example:**
```typescript
const digester = await FileCrypto.calculateChecksum('file.bin', 'sha256')
console.log(digester.hex())
```

**Hash Algorithm Options:**

The `calculateChecksum()` method accepts an optional `HashOptions` parameter from Node.js crypto, which can include:
- `outputLength?: number` - For XOF hash functions
- Other algorithm-specific options

See [Node.js crypto documentation](https://nodejs.org/api/crypto.html#crypto_crypto_createhash_algorithm_options) for details.

### `Digester`

Result object from checksum calculation with multiple output formats.

#### `digester.hex()`

Returns the hash as a hexadecimal string.

**Returns:** `string`

#### `digester.base64()`

Returns the hash as a base64-encoded string.

**Returns:** `string`

#### `digester.binary()`

Returns the hash as a binary string.

**Returns:** `string`

#### `digester.buffer()`

Returns the hash as a Buffer.

**Returns:** `Buffer`

### Hash Algorithms

The following hash algorithms are supported for checksum calculation:

- `'sha256'` - SHA-256 (recommended)
- `'sha512'` - SHA-512
- `'sha3-256'` - SHA3-256
- `'sha3-512'` - SHA3-512
- `'sha3-384'` - SHA3-384
- `'sha3-224'` - SHA3-224
- `'ripemd160'` - RIPEMD-160
- `'md5'` - MD5 (for compatibility only, not recommended for security)
- `'sha1'` - SHA-1 (for compatibility only, not recommended for security)

**Note:** MD5 and SHA-1 are available for checksums but are not used for encryption key derivation, which always uses SHA-256.

## Complete Example

```typescript
import { FileCrypto } from '@nolawnchairs/file-crypto'
import { join } from 'node:path'
import { ENCRYPTION_KEY } from 'some-secret-location'

async function main() {
  // Create encryption context
  const context = FileCrypto.createContext(ENCRYPTION_KEY)

  const source = join(__dirname, 'data/input.bin')
  const encrypted = join(__dirname, 'data/encrypted.dat')
  const decrypted = join(__dirname, 'data/decrypted.bin')

  // Calculate original checksum
  const originalChecksum = await FileCrypto.calculateChecksum(source, 'sha256')
  console.log('Original checksum:', originalChecksum.hex())

  // Encrypt
  const encryptor = context.newEncryptor(source, encrypted)
  await encryptor.write()
  console.log('Encryption complete')

  // Decrypt
  const decryptor = context.newDecryptor(encrypted, decrypted)
  await decryptor.write()
  console.log('Decryption complete')

  // Verify decrypted file
  const decryptedChecksum = await FileCrypto.calculateChecksum(decrypted, 'sha256')
  console.log('Decrypted checksum:', decryptedChecksum.hex())
  console.log('Checksums match:', originalChecksum.hex() === decryptedChecksum.hex())
}

main().catch(console.error)
```

## File Format

Encrypted files use the following format:

```
[12-byte nonce][ciphertext][16-byte auth tag]
```

- **Nonce (12 bytes)**: Random initialization vector for AES-GCM
- **Ciphertext**: Encrypted file data
- **Auth Tag (16 bytes)**: GCM authentication tag for integrity verification

The nonce is written first, followed by the encrypted data stream, with the authentication tag appended at the end.

## Security Notes

- **Key Requirements**: Keys must be at least 32 bytes (UTF-8) by default. Use longer keys for higher security requirements.
- **Key Derivation**: The provided key is hashed using SHA-256 to derive the 32-byte AES-256 key. This ensures consistent key length regardless of input key size.
- **Encryption**: Uses AES-256-GCM, which provides both confidentiality and authenticity.
- **Random Nonce**: Each encryption operation uses a cryptographically secure random nonce.
- **Constant Memory**: Decryption uses file range reads to access the nonce and tag without buffering ciphertext, making it safe for very large files.

## Performance

- **Streaming**: All operations use Node.js streams for efficient memory usage
- **Large Files**: Designed for 1GB+ files with constant-memory operation
- **Configurable Buffers**: Adjust `highWaterMark` to balance memory usage and throughput
- **Efficient I/O**: Uses `fs.promises.open` for fixed-size reads (nonce/tag) to minimize overhead

## License

ISC

