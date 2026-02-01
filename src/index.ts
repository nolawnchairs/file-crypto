import { createHash, createCipheriv, createDecipheriv, randomBytes, type HashOptions, Hash } from 'node:crypto'
import { createReadStream, createWriteStream, type WriteStream } from 'node:fs'
import { Readable, type Writable, PassThrough } from 'node:stream'

type HashAlgorithm =
  | 'sha256'
  | 'sha512'
  | 'md5'
  | 'ripemd160'
  | 'sha1'
  | 'sha3-256'
  | 'sha3-512'
  | 'sha3-384'
  | 'sha3-224'

type SecureAlgorithm = Exclude<HashAlgorithm, 'md5' | 'sha1'>

export class FileCrypto {

  static sha256(key: string, options?: HashOptions) {
    return new CryptoContext(key, 'sha256', options)
  }

  static sha512(key: string, options?: HashOptions) {
    return new CryptoContext(key, 'sha512', options)
  }

  static ripemd160(key: string, options?: HashOptions) {
    return new CryptoContext(key, 'ripemd160', options)
  }

  static sha3_256(key: string, options?: HashOptions) {
    return new CryptoContext(key, 'sha3-256', options)
  }

  static sha3_512(key: string, options?: HashOptions) {
    return new CryptoContext(key, 'sha3-512', options)
  }

  static sha3_384(key: string, options?: HashOptions) {
    return new CryptoContext(key, 'sha3-384', options)
  }

  static sha3_224(key: string, options?: HashOptions) {
    return new CryptoContext(key, 'sha3-224', options)
  }

  static async calculateChecksum(
    source: Readable | string,
    algorithm: HashAlgorithm,
    options?: HashOptions
  ): Promise<Digester> {
    // Create hash instance
    const hash = createHash(algorithm, options)

    // Convert string path to stream if needed
    const stream = typeof source === 'string'
      ? createReadStream(source)
      : source

    // Read all data from stream and update hash
    return new Promise<Digester>((resolve, reject) => {
      stream.on('data', (chunk: Buffer) => {
        hash.update(chunk)
      })

      stream.on('end', () => {
        resolve(new Digester(hash))
      })

      stream.on('error', (error) => {
        reject(error)
      })
    })
  }
}

export class Digester {
  constructor(readonly hash: Hash) { }

  hex() {
    return this.hash.digest('hex')
  }

  base64() {
    return this.hash.digest('base64')
  }

  binary() {
    return this.hash.digest('binary')
  }
}

export class CryptoContext {
  constructor(
    readonly key: string,
    readonly algorithm: SecureAlgorithm,
    readonly hashOptions?: HashOptions
  ) { }

  newEncryptor(source: Readable, target: WriteStream): FileEncrypt
  newEncryptor(sourcePath: string, targetPath: string): FileEncrypt
  newEncryptor(source: Readable | string, target: WriteStream | string): FileEncrypt {
    // Convert string paths to streams if needed
    const read = typeof source === 'string'
      ? createReadStream(source)
      : source

    const write = typeof target === 'string'
      ? createWriteStream(target)
      : target

    return new FileEncrypt(this, read, write)
  }

  newDecryptor(source: Readable, target: WriteStream): FileDecrypt
  newDecryptor(sourcePath: string, targetPath: string): FileDecrypt
  newDecryptor(source: Readable | string, target: WriteStream | string): FileDecrypt {
    // Convert string paths to streams if needed
    const read = typeof source === 'string'
      ? createReadStream(source)
      : source

    const write = typeof target === 'string'
      ? createWriteStream(target)
      : target

    return new FileDecrypt(this, read, write)
  }
}

export class FileEncrypt {
  constructor(
    private readonly context: CryptoContext,
    private readonly readStream: Readable,
    private readonly writeStream: WriteStream | Writable
  ) { }

  /**
   * Writes encrypted data to the provided write stream.
   * Uses the read stream provided to the constructor.
   * @returns A Promise that resolves when all data has been written.
   */
  async write(): Promise<void> {
    // Derive encryption key from the hash algorithm
    const hash = createHash(this.context.algorithm, this.context.hashOptions)
    hash.update(this.context.key)
    const key = hash.digest().subarray(0, 32) // Use first 32 bytes for AES-256

    // Generate a random IV (16 bytes for AES)
    const iv = randomBytes(16)

    // Write IV to the stream first (needed for decryption)
    await new Promise<void>((resolve, reject) => {
      this.writeStream.write(iv, (error) => {
        if (error) {
          reject(error)
        } else {
          resolve()
        }
      })
    })

    // Create cipher using AES-256-CBC
    const cipher = createCipheriv('aes-256-cbc', key, iv)

    // Handle Readable stream input
    return new Promise<void>((resolve, reject) => {
      let hasError = false

      cipher.on('data', (chunk: Buffer) => {
        if (hasError) return
        const writeSuccess = this.writeStream.write(chunk)
        if (!writeSuccess) {
          // Wait for drain event if buffer is full
          this.writeStream.once('drain', () => {
            // Continue writing when drain occurs
          })
        }
      })

      cipher.on('end', () => {
        if (hasError) return
        this.writeStream.end()
        resolve()
      })

      cipher.on('error', (error) => {
        hasError = true
        reject(error)
      })

      this.readStream.on('error', (error) => {
        hasError = true
        reject(error)
      })

      // Pipe data through cipher
      this.readStream.pipe(cipher)
    })
  }
}

export class FileDecrypt {
  constructor(
    private readonly context: CryptoContext,
    private readonly readStream: Readable,
    private readonly writeStream: WriteStream | Writable
  ) { }

  /**
   * Writes decrypted data to the provided write stream.
   * Uses the read stream provided to the constructor.
   * @returns A Promise that resolves when all data has been written.
   */
  async write(): Promise<void> {
    // Derive decryption key from the hash algorithm (same as encryption)
    const hash = createHash(this.context.algorithm, this.context.hashOptions)
    hash.update(this.context.key)
    const key = hash.digest().subarray(0, 32) // Use first 32 bytes for AES-256

    // Read IV from the stream first (16 bytes)
    const { iv, remainingStream } = await new Promise<{ iv: Buffer; remainingStream: Readable }>((resolve, reject) => {
      const chunks: Buffer[] = []
      let totalLength = 0
      const ivLength = 16

      this.readStream.on('data', (chunk: Buffer) => {
        chunks.push(chunk)
        totalLength += chunk.length

        if (totalLength >= ivLength) {
          // We have enough data for the IV
          const ivBuffer = Buffer.concat(chunks, totalLength)
          const iv = ivBuffer.subarray(0, ivLength)
          const remaining = ivBuffer.subarray(ivLength)

          // Remove listeners to stop reading
          this.readStream.removeAllListeners('data')
          this.readStream.removeAllListeners('error')
          this.readStream.removeAllListeners('end')

          // Create a new stream with remaining data
          const remainingStream = new PassThrough()
          if (remaining.length > 0) {
            remainingStream.push(remaining)
          }

          // Continue piping the rest of the stream
          this.readStream.on('data', (chunk: Buffer) => {
            remainingStream.push(chunk)
          })

          this.readStream.on('end', () => {
            remainingStream.push(null)
          })

          this.readStream.on('error', (error) => {
            remainingStream.destroy(error)
          })

          resolve({ iv, remainingStream })
        }
      })

      this.readStream.on('error', (error) => {
        reject(error)
      })
    })

    // Create decipher using AES-256-CBC
    const decipher = createDecipheriv('aes-256-cbc', key, iv)

    // Handle Readable stream input
    return new Promise<void>((resolve, reject) => {
      let hasError = false

      decipher.on('data', (chunk: Buffer) => {
        if (hasError) return
        const writeSuccess = this.writeStream.write(chunk)
        if (!writeSuccess) {
          // Wait for drain event if buffer is full
          this.writeStream.once('drain', () => {
            // Continue writing when drain occurs
          })
        }
      })

      decipher.on('end', () => {
        if (hasError) return
        this.writeStream.end()
        resolve()
      })

      decipher.on('error', (error) => {
        hasError = true
        reject(error)
      })

      remainingStream.on('error', (error) => {
        hasError = true
        reject(error)
      })

      // Pipe remaining data through decipher
      remainingStream.pipe(decipher)
    })
  }
}
