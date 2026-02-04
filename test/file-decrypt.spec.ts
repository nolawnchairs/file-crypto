import { FileCrypto } from '../src'
import { MockFileSystem } from './mocks/stream-mocks'
import * as fs from 'node:fs'
import { promises as fsPromises } from 'node:fs'
import { KEY, NONCE_LENGTH, TAG_LENGTH } from './constants'

describe('FileDecrypt', () => {
  let mockFS: MockFileSystem

  beforeEach(() => {
    mockFS = new MockFileSystem()

    jest.spyOn(fs, 'createReadStream').mockImplementation(mockFS.createReadStream() as typeof fs.createReadStream)
    jest.spyOn(fs, 'createWriteStream').mockImplementation(mockFS.createWriteStream() as typeof fs.createWriteStream)
    jest.spyOn(fs, 'statSync').mockImplementation(mockFS.createStatSync() as typeof fs.statSync)
    jest.spyOn(fsPromises, 'open').mockImplementation(mockFS.createOpen() as typeof fsPromises.open)
  })

  afterEach(() => {
    jest.restoreAllMocks()
    mockFS.clear()
  })

  describe('write', () => {
    it('should decrypt a small encrypted file correctly', async () => {
      // First encrypt a file
      const sourceData = Buffer.from('Hello, World! This is a test file.', 'utf8')
      const sourcePath = '/test/source.bin'
      const encryptedPath = '/test/encrypted.dat'
      const decryptedPath = '/test/decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      // Now decrypt it
      const decryptor = context.newDecryptor(encryptedPath, decryptedPath)
      await decryptor.write()

      const decryptedData = mockFS.getFile(decryptedPath)
      expect(decryptedData).toBeDefined()
      expect(decryptedData).toEqual(sourceData)
    })

    it('should decrypt a 1MB encrypted file correctly', async () => {
      const sourceData = Buffer.alloc(1024 * 1024, 0x42) // 1MB of 0x42 bytes
      const sourcePath = '/test/large-source.bin'
      const encryptedPath = '/test/large-encrypted.dat'
      const decryptedPath = '/test/large-decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      const decryptor = context.newDecryptor(encryptedPath, decryptedPath)
      await decryptor.write()

      const decryptedData = mockFS.getFile(decryptedPath)
      expect(decryptedData).toBeDefined()
      expect(decryptedData).toEqual(sourceData)
    })

    it('should decrypt empty file correctly', async () => {
      const sourceData = Buffer.alloc(0)
      const sourcePath = '/test/empty.bin'
      const encryptedPath = '/test/empty-encrypted.dat'
      const decryptedPath = '/test/empty-decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      const decryptor = context.newDecryptor(encryptedPath, decryptedPath)
      await decryptor.write()

      const decryptedData = mockFS.getFile(decryptedPath)
      expect(decryptedData).toBeDefined()
      expect(decryptedData!.length).toBe(0)
    })

    it('should throw error for file too small (smaller than nonce + tag)', async () => {
      const invalidData = Buffer.alloc(NONCE_LENGTH + TAG_LENGTH - 1) // Too small
      const invalidPath = '/test/invalid.dat'
      const decryptedPath = '/test/decrypted.bin'

      mockFS.createFile(invalidPath, invalidData)

      const context = FileCrypto.createContext(KEY)
      const decryptor = context.newDecryptor(invalidPath, decryptedPath)

      await expect(decryptor.write()).rejects.toThrow(/File too small/)
    })

    it('should throw error for corrupted auth tag', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const encryptedPath = '/test/encrypted.dat'
      const corruptedPath = '/test/corrupted.dat'
      const decryptedPath = '/test/decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      // Corrupt the auth tag
      const encryptedData = mockFS.getFile(encryptedPath)!
      const corruptedData = Buffer.from(encryptedData)
      corruptedData[corruptedData.length - 1] ^= 0xFF // Flip last byte of tag
      mockFS.createFile(corruptedPath, corruptedData)

      const decryptor = context.newDecryptor(corruptedPath, decryptedPath)
      await expect(decryptor.write()).rejects.toThrow()
    })

    it('should throw error for corrupted nonce', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const encryptedPath = '/test/encrypted.dat'
      const corruptedPath = '/test/corrupted.dat'
      const decryptedPath = '/test/decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      // Corrupt the nonce
      const encryptedData = mockFS.getFile(encryptedPath)!
      const corruptedData = Buffer.from(encryptedData)
      corruptedData[0] ^= 0xFF // Flip first byte of nonce
      mockFS.createFile(corruptedPath, corruptedData)

      const decryptor = context.newDecryptor(corruptedPath, decryptedPath)
      await expect(decryptor.write()).rejects.toThrow()
    })

    it('should throw error for wrong key', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const encryptedPath = '/test/encrypted.dat'
      const decryptedPath = '/test/decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context1 = FileCrypto.createContext(KEY)
      const encryptor = context1.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      // Try to decrypt with different key
      const wrongKey = Buffer.from('different-key-that-is-at-least-32-bytes-long-for-testing', 'utf8')
      const context2 = FileCrypto.createContext(wrongKey)
      const decryptor = context2.newDecryptor(encryptedPath, decryptedPath)

      await expect(decryptor.write()).rejects.toThrow()
    })

    it('should throw error when source file does not exist', async () => {
      const sourcePath = '/test/nonexistent.dat'
      const decryptedPath = '/test/decrypted.bin'

      const context = FileCrypto.createContext(KEY)
      const decryptor = context.newDecryptor(sourcePath, decryptedPath)

      await expect(decryptor.write()).rejects.toThrow()
    })

    it('should use custom highWaterMark from context', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const encryptedPath = '/test/encrypted.dat'
      const decryptedPath = '/test/decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      const customHighWaterMark = 2 * 1024 * 1024 // 2MB
      const context2 = FileCrypto.createContext(KEY, { highWaterMark: customHighWaterMark })
      const decryptor = context2.newDecryptor(encryptedPath, decryptedPath)

      const createReadStreamSpy = jest.spyOn(fs, 'createReadStream')
      const createWriteStreamSpy = jest.spyOn(fs, 'createWriteStream')

      await decryptor.write()

      // Check that ciphertext stream uses custom highWaterMark
      const readStreamCalls = createReadStreamSpy.mock.calls
      const rangeReadCall = readStreamCalls.find((call) =>
        call[0] === encryptedPath &&
        typeof call[1] === 'object' &&
        call[1] !== null &&
        'start' in call[1] &&
        call[1].start === NONCE_LENGTH
      )
      expect(rangeReadCall).toBeDefined()
      if (rangeReadCall && typeof rangeReadCall[1] === 'object' && rangeReadCall[1] !== null && 'highWaterMark' in rangeReadCall[1]) {
        expect(rangeReadCall[1].highWaterMark).toBe(customHighWaterMark)
      }
      expect(createWriteStreamSpy).toHaveBeenCalledWith(
        decryptedPath,
        expect.objectContaining({ highWaterMark: customHighWaterMark })
      )
    })

    it('should read nonce from start and tag from end', async () => {
      const sourceData = Buffer.from('Test data', 'utf8')
      const sourcePath = '/test/source.bin'
      const encryptedPath = '/test/encrypted.dat'
      const decryptedPath = '/test/decrypted.bin'

      mockFS.createFile(sourcePath, sourceData)

      const context = FileCrypto.createContext(KEY)
      const encryptor = context.newEncryptor(sourcePath, encryptedPath)
      await encryptor.write()

      const openSpy = jest.spyOn(fsPromises, 'open')
      const decryptor = context.newDecryptor(encryptedPath, decryptedPath)
      await decryptor.write()

      // Verify that readFixedBytes was called for nonce and tag
      // The open spy should be called twice (once for nonce, once for tag)
      expect(openSpy).toHaveBeenCalledTimes(2)

      // Verify decryption worked
      const decryptedData = mockFS.getFile(decryptedPath)
      expect(decryptedData).toEqual(sourceData)
    })
  })
})
