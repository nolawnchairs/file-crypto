import { FileCrypto } from '../src'
import { KEY } from './constants'

describe('FileCrypto', () => {
  describe('createContext', () => {
    it('should create a context', () => {
      const context = FileCrypto.createContext(KEY)
      expect(context).toBeDefined()
    })
    it('should throw an error if the key is too short', () => {
      expect(() => FileCrypto.createContext(Buffer.alloc(15))).toThrow()
    })
    it('should enforce minKeyBytes', () => {
      expect(() => FileCrypto.createContext(Buffer.alloc(32), { minKeyBytes: 64 })).toThrow()
    })
  })
  describe('createChecksumContext', () => {
    it('should create a checksum context', () => {
      const context = FileCrypto.createChecksumContext('sha256')
      expect(context).toBeDefined()
    })
  })
})
