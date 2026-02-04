import { FileCrypto } from '../src'
import { KEY } from './constants'

describe('FileCrypto', () => {
  describe('createContext', () => {
    it('should create a context', () => {
      const context = FileCrypto.createContext(KEY)
      expect(context).toBeDefined()
    })
  })
  describe('createChecksumContext', () => {
    it('should create a checksum context', () => {
      const context = FileCrypto.createChecksumContext('sha256')
      expect(context).toBeDefined()
    })
  })
})
