import { createHash, createCipheriv, createDecipheriv, randomBytes, type HashOptions, Hash } from 'node:crypto'
import { createReadStream, createWriteStream, statSync, promises as fsPromises } from 'node:fs'
import { Readable, Transform, pipeline } from 'node:stream'
import { promisify } from 'node:util'

export type CryptoContextOptions = {
  minKeyBytes?: number
  highWaterMark?: number
}

type DecipherivWithAuthTag = ReturnType<typeof createDecipheriv> & {
  setAuthTag: (tag: Buffer) => void
}

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
const HIGH_WATER_MARK = 1024 * 1024 // 1MB buffer for better performance

const pipelineAsync = promisify(pipeline)

function deriveKey(key: Buffer, minKeyBytes: number): Buffer {
  if (key.length < minKeyBytes) {
    throw new Error(`Key must be at least ${minKeyBytes} bytes. Provided key is ${key.length} bytes.`)
  }
  const hash = createHash('sha256')
  hash.update(key)
  return hash.digest()
}

export class FileCrypto {

  static createContext(key: Buffer, options?: CryptoContextOptions): ICryptoContext {
    const minKeyBytes = options?.minKeyBytes ?? MIN_KEY_BYTES
    const highWaterMark = options?.highWaterMark ?? HIGH_WATER_MARK
    return new CryptoContext(key, {
      minKeyBytes,
      highWaterMark,
    })
  }

  static createChecksumContext(algorithm: HashAlgorithm, options?: HashOptions): IChecksumContext {
    return new ChecksumContext(algorithm, options)
  }

  static async calculateChecksum(
    source: Readable | string,
    algorithm: HashAlgorithm,
    options?: HashOptions
  ): Promise<Digester> {
    const context = new ChecksumContext(algorithm, options)
    return context.calculate(source)
  }
}

export interface IChecksumContext {
  calculate(source: Readable | string): Promise<Digester>
}

export class ChecksumContext implements IChecksumContext {
  constructor(
    readonly algorithm: HashAlgorithm,
    readonly options?: HashOptions
  ) { }

  async calculate(source: Readable | string): Promise<Digester> {
    const hash = createHash(this.algorithm, this.options)
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

export interface ICryptoContext {
  newEncryptor(sourcePath: string, targetPath: string): FileEncrypt
  newDecryptor(sourcePath: string, targetPath: string): FileDecrypt
}

export class CryptoContext implements ICryptoContext {
  private readonly derivedKey: Buffer
  private readonly highWaterMark: number

  constructor(key: Buffer, options: Required<CryptoContextOptions>) {
    this.derivedKey = deriveKey(key, options.minKeyBytes)
    this.highWaterMark = options.highWaterMark
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

  getHighWaterMark(): number {
    return this.highWaterMark
  }
}

export class FileEncrypt {
  constructor(
    private readonly context: CryptoContext,
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

    const highWaterMark = this.context.getHighWaterMark()
    const readStream = createReadStream(this.sourcePath, {
      highWaterMark,
    })
    const writeStream = createWriteStream(this.targetPath, {
      highWaterMark,
    })

    try {
      await new Promise<void>((resolve, reject) => {
        writeStream.write(nonce, (error) => {
          if (error) reject(error)
          else resolve()
        })
      })

      const cipher = createCipheriv('aes-256-gcm', key, nonce)
      let authTag: Buffer | null = null

      cipher.once('end', () => {
        authTag = cipher.getAuthTag()
      })

      const tagAppender = new Transform({
        transform(chunk: Buffer, encoding, callback) {
          callback(null, chunk)
        },
        flush(callback) {
          if (!authTag) {
            callback(new Error('Auth tag not available - cipher may not have finalized'))
            return
          }
          this.push(authTag)
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
    private readonly context: CryptoContext,
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

    const nonce = await this.readFixedBytes(sourcePath, nonceStart, NONCE_LENGTH)
    const tag = await this.readFixedBytes(sourcePath, tagStart, TAG_LENGTH)
    const highWaterMark = this.context.getHighWaterMark()
    const ciphertextStream = createReadStream(sourcePath, {
      start: ciphertextStart,
      end: ciphertextEnd - 1,
      highWaterMark,
    })
    const writeStream = createWriteStream(targetPath, {
      highWaterMark,
    })

    const decipher = createDecipheriv('aes-256-gcm', key, nonce) as DecipherivWithAuthTag
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
   * Reads a fixed number of bytes from a file at a specific position.
   * Uses fs.promises.open + read for efficient fixed-size reads.
   * Used for reading nonce (12 bytes from start) and tag (16 bytes from end).
   */
  private async readFixedBytes(filePath: string, position: number, length: number): Promise<Buffer> {
    const fileHandle = await fsPromises.open(filePath, 'r')
    try {
      const buffer = Buffer.alloc(length)
      let bytesRead = 0
      let offset = 0

      while (bytesRead < length) {
        const result = await fileHandle.read(buffer, offset, length - bytesRead, position + bytesRead)
        if (result.bytesRead === 0) {
          throw new Error(`Unexpected end of file: needed ${length} bytes, got ${bytesRead}`)
        }
        bytesRead += result.bytesRead
        offset += result.bytesRead
      }

      if (bytesRead !== length) {
        throw new Error(`Expected ${length} bytes, got ${bytesRead}`)
      }

      return buffer
    } finally {
      await fileHandle.close()
    }
  }
}
