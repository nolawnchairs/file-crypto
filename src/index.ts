import { createHash, createCipheriv, createDecipheriv, randomBytes, type HashOptions, Hash } from 'node:crypto'
import { createReadStream, createWriteStream, statSync } from 'node:fs'
import { Readable, Transform, pipeline } from 'node:stream'
import { promisify } from 'node:util'

const pipelineAsync = promisify(pipeline)

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

const NONCE_LENGTH = 12
const TAG_LENGTH = 16
const MIN_KEY_BYTES = 32

function deriveKey(key: string): Buffer {
  const keyBytes = Buffer.from(key, 'utf8')
  if (keyBytes.length < MIN_KEY_BYTES) {
    throw new Error(`Key must be at least ${MIN_KEY_BYTES} bytes (UTF-8). Provided key is ${keyBytes.length} bytes.`)
  }
  const hash = createHash('sha256')
  hash.update(keyBytes)
  return hash.digest()
}

export class FileCrypto {
  static withKey(key: string, options?: { minKeyBytes?: number }): FileCryptoContext {
    const minBytes = options?.minKeyBytes ?? MIN_KEY_BYTES
    const keyBytes = Buffer.from(key, 'utf8')
    if (keyBytes.length < minBytes) {
      throw new Error(`Key must be at least ${minBytes} bytes (UTF-8). Provided key is ${keyBytes.length} bytes.`)
    }
    return new FileCryptoContext(key)
  }

  static async calculateChecksum(
    source: Readable | string,
    algorithm: HashAlgorithm,
    options?: HashOptions
  ): Promise<Digester> {
    const hash = createHash(algorithm, options)
    const stream = typeof source === 'string'
      ? createReadStream(source)
      : source

    return new Promise<Digester>((resolve, reject) => {
      stream.on('data', (chunk: Buffer) => {
        hash.update(chunk)
      })

      stream.on('end', () => {
        resolve(new Digester(hash))
      })

      stream.on('error', (error: Error) => {
        stream.destroy()
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

  buffer() {
    return this.hash.digest()
  }
}

export class FileCryptoContext {
  private readonly derivedKey: Buffer

  constructor(readonly key: string) {
    this.derivedKey = deriveKey(key)
  }

  /**
   * Creates an encryptor from file paths.
   * @param sourcePath - Path to the source file to encrypt
   * @param targetPath - Path to the output file for encrypted data
   */
  newEncryptor(sourcePath: string, targetPath: string): FileEncrypt {
    return new FileEncrypt(this, sourcePath, targetPath)
  }

  /**
   * Creates a decryptor from file paths.
   * Uses constant-memory streaming for large files (1GB+) by reading the auth tag
   * from the end of the file without buffering ciphertext.
   * @param sourcePath - Path to the encrypted file to decrypt
   * @param targetPath - Path to the output file for decrypted data
   */
  newDecryptor(sourcePath: string, targetPath: string): FileDecrypt {
    return new FileDecrypt(this, sourcePath, targetPath)
  }

  getDerivedKey(): Buffer {
    return this.derivedKey
  }
}

export class FileEncrypt {
  constructor(
    private readonly context: FileCryptoContext,
    private readonly sourcePath: string,
    private readonly targetPath: string
  ) { }

  /**
   * Encrypts data using AES-256-GCM and writes to the output file.
   * Format: [12-byte nonce][ciphertext][16-byte auth tag]
   * @returns A Promise that resolves when all data has been written and flushed.
   */
  async write(): Promise<void> {
    const key = this.context.getDerivedKey()
    const nonce = randomBytes(NONCE_LENGTH)

    const readStream = createReadStream(this.sourcePath)
    const writeStream = createWriteStream(this.targetPath)

    try {
      await new Promise<void>((resolve, reject) => {
        writeStream.write(nonce, (error) => {
          if (error) reject(error)
          else resolve()
        })
      })

      const cipher = createCipheriv('aes-256-gcm', key, nonce)
      const tagAppender = new Transform({
        transform(chunk: Buffer, encoding, callback) {
          callback(null, chunk)
        },
        flush(callback) {
          const tag = cipher.getAuthTag()
          this.push(tag)
          callback()
        },
      })

      await pipelineAsync(
        readStream,
        cipher,
        tagAppender,
        writeStream
      )
    } catch (error) {
      readStream.destroy()
      writeStream.destroy()
      throw error
    }
  }
}

export class FileDecrypt {
  constructor(
    private readonly context: FileCryptoContext,
    private readonly sourcePath: string,
    private readonly targetPath: string
  ) { }

  /**
   * Decrypts data from AES-256-GCM format.
   * Format: [12-byte nonce][ciphertext][16-byte auth tag]
   *
   * Uses constant-memory streaming for large files (1GB+) by reading the nonce from the
   * start and tag from the end without buffering ciphertext in memory.
   *
   * @returns A Promise that resolves when all data has been written and flushed.
   */
  async write(): Promise<void> {
    const key = this.context.getDerivedKey()
    await this.writeFromFile(this.sourcePath, this.targetPath, key)
  }

  /**
   * Decrypts from a file using constant-memory streaming.
   * Reads nonce from start (12 bytes), tag from end (16 bytes), and streams ciphertext from middle.
   * This is the safe path for 1GB+ files as it does not buffer ciphertext in memory.
   */
  private async writeFromFile(sourcePath: string, targetPath: string, key: Buffer): Promise<void> {
    const stats = statSync(sourcePath)
    const fileSize = stats.size

    if (fileSize < NONCE_LENGTH + TAG_LENGTH) {
      throw new Error(`File too small: expected at least ${NONCE_LENGTH + TAG_LENGTH} bytes (nonce + tag), got ${fileSize}`)
    }

    const nonceStart = 0
    const ciphertextStart = NONCE_LENGTH
    const ciphertextEnd = fileSize - TAG_LENGTH
    const tagStart = fileSize - TAG_LENGTH

    const nonce = await this.readFileRange(sourcePath, nonceStart, NONCE_LENGTH)
    const tag = await this.readFileRange(sourcePath, tagStart, TAG_LENGTH)
    const ciphertextStream = createReadStream(sourcePath, { start: ciphertextStart, end: ciphertextEnd - 1 })
    const writeStream = createWriteStream(targetPath)

    const decipher = createDecipheriv('aes-256-gcm', key, nonce) as ReturnType<typeof createDecipheriv> & { setAuthTag: (tag: Buffer) => void }
    decipher.setAuthTag(tag)

    try {
      await pipelineAsync(
        ciphertextStream,
        decipher,
        writeStream
      )
    } catch (error) {
      ciphertextStream.destroy()
      writeStream.destroy()
      throw error
    }
  }

  /**
   * Reads an exact byte range from a file.
   * Used for reading nonce (12 bytes from start) and tag (16 bytes from end).
   */
  private async readFileRange(filePath: string, start: number, length: number): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const stream = createReadStream(filePath, { start, end: start + length - 1 })
      const chunks: Buffer[] = []
      let totalLength = 0

      const cleanup = () => {
        stream.removeAllListeners()
        stream.destroy()
      }

      stream.on('data', (chunk: Buffer) => {
        chunks.push(chunk)
        totalLength += chunk.length
      })

      stream.on('end', () => {
        cleanup()
        if (totalLength !== length) {
          reject(new Error(`Expected ${length} bytes, got ${totalLength}`))
        } else {
          resolve(Buffer.concat(chunks, totalLength))
        }
      })

      stream.on('error', (error: Error) => {
        cleanup()
        reject(error)
      })

      stream.on('close', () => {
        if (totalLength < length) {
          cleanup()
          reject(new Error(`Unexpected end of stream: needed ${length} bytes, got ${totalLength}`))
        }
      })
    })
  }
}
