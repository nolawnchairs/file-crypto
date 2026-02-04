import { FileCrypto } from '../src'
import { MockFileSystem } from './mocks/stream-mocks'
import * as fs from 'node:fs'
import { KEY, NONCE_LENGTH, TAG_LENGTH } from './constants'

describe('FileEncrypt', () => {
  let mockFS: MockFileSystem

  beforeEach(() => {
    mockFS = new MockFileSystem()

    jest.spyOn(fs, 'createReadStream').mockImplementation(mockFS.createReadStream() as typeof fs.createReadStream)
    jest.spyOn(fs, 'createWriteStream').mockImplementation(mockFS.createWriteStream() as typeof fs.createWriteStream)
  })

  afterEach(() => {
    jest.restoreAllMocks()
    mockFS.clear()
  })

  describe('write', () => {
    it('should encrypt a small file correctly', async () => {
      const sourceData = Buffer.from('Hello, World! This is a test file.', 'utf8')
      const sourcePath = '/test/source.bin'
      const targetPath = '/test/encrypted.dat'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, targetPath)
      await encryptor.write()

      const encryptedData = mockFS.getFile(targetPath)
      expect(encryptedData).toBeDefined()
      expect(encryptedData!.length).toBeGreaterThan(sourceData.length)

      // Verify format: [12-byte nonce][ciphertext][16-byte tag]
      expect(encryptedData!.length).toBe(NONCE_LENGTH + sourceData.length + TAG_LENGTH)
    })

    it('should encrypt a 1MB file correctly', async () => {
      const sourceData = Buffer.alloc(1024 * 1024, 0x42) // 1MB of 0x42 bytes
      const sourcePath = '/test/large-source.bin'
      const targetPath = '/test/large-encrypted.dat'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, targetPath)
      await encryptor.write()

      const encryptedData = mockFS.getFile(targetPath)
      expect(encryptedData).toBeDefined()
      expect(encryptedData!.length).toBe(NONCE_LENGTH + sourceData.length + TAG_LENGTH)
    })

    it('should write nonce at the beginning', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const targetPath = '/test/encrypted.dat'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, targetPath)
      await encryptor.write()

      const encryptedData = mockFS.getFile(targetPath)!
      const nonce = encryptedData.subarray(0, NONCE_LENGTH)

      expect(nonce.length).toBe(NONCE_LENGTH)
      // Nonce should be random (not all zeros)
      expect(nonce.some((byte) => byte !== 0)).toBe(true)
    })

    it('should write auth tag at the end', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const targetPath = '/test/encrypted.dat'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, targetPath)
      await encryptor.write()

      const encryptedData = mockFS.getFile(targetPath)!
      const tag = encryptedData.subarray(encryptedData.length - TAG_LENGTH)

      expect(tag.length).toBe(TAG_LENGTH)
      // Tag should not be all zeros
      expect(tag.some((byte) => byte !== 0)).toBe(true)
    })

    it('should produce different nonces for each encryption', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const targetPath1 = '/test/encrypted1.dat'
      const targetPath2 = '/test/encrypted2.dat'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor1 = context.newEncryptor(sourcePath, targetPath1)
      await encryptor1.write()

      const encryptor2 = context.newEncryptor(sourcePath, targetPath2)
      await encryptor2.write()

      const encrypted1 = mockFS.getFile(targetPath1)!
      const encrypted2 = mockFS.getFile(targetPath2)!

      const nonce1 = encrypted1.subarray(0, NONCE_LENGTH)
      const nonce2 = encrypted2.subarray(0, NONCE_LENGTH)

      // Nonces should be different (very high probability)
      expect(Buffer.compare(nonce1, nonce2)).not.toBe(0)
    })

    it('should handle empty file', async () => {
      const sourceData = Buffer.alloc(0)
      const sourcePath = '/test/empty.bin'
      const targetPath = '/test/empty-encrypted.dat'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, targetPath)
      await encryptor.write()

      const encryptedData = mockFS.getFile(targetPath)
      expect(encryptedData).toBeDefined()
      expect(encryptedData!.length).toBe(NONCE_LENGTH + TAG_LENGTH)
    })

    it('should handle read stream errors', async () => {
      const sourcePath = '/test/nonexistent.bin'
      const targetPath = '/test/encrypted.dat'

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, targetPath)

      await expect(encryptor.write()).rejects.toThrow()
    })

    it('should use custom highWaterMark from context', async () => {
      const sourceData = Buffer.alloc(1024 * 1024, 0x42)
      const sourcePath = '/test/source.bin'
      const targetPath = '/test/encrypted.dat'

      mockFS.createFile(sourcePath, sourceData)

      const customHighWaterMark = 2 * 1024 * 1024 // 2MB
      const context = FileCrypto.createContext(KEY, { highWaterMark: customHighWaterMark })
      const encryptor = context.newEncryptor(sourcePath, targetPath)

      const createReadStreamSpy = jest.spyOn(fs, 'createReadStream')
      const createWriteStreamSpy = jest.spyOn(fs, 'createWriteStream')

      await encryptor.write()

      expect(createReadStreamSpy).toHaveBeenCalledWith(
        sourcePath,
        expect.objectContaining({ highWaterMark: customHighWaterMark })
      )
      expect(createWriteStreamSpy).toHaveBeenCalledWith(
        targetPath,
        expect.objectContaining({ highWaterMark: customHighWaterMark })
      )
    })
  })
})
