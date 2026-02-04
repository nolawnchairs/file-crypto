import { Readable, Writable } from 'node:stream'
import { type WriteStream } from 'node:fs'

/**
 * Creates a mock Readable stream that simulates reading from a file.
 * The data is provided as a Buffer and will be streamed in chunks.
 */
export function createMockReadStream(data: Buffer, options?: { highWaterMark?: number }): Readable {
  let offset = 0
  const chunkSize = options?.highWaterMark ?? 64 * 1024

  const stream = new Readable({
    read() {
      // Push one chunk per read() call
      if (offset >= data.length) {
        this.push(null) // End of stream
        return
      }

      const chunk = data.subarray(offset, Math.min(offset + chunkSize, data.length))
      offset += chunk.length
      this.push(chunk)
    },
    highWaterMark: options?.highWaterMark,
  })

  return stream
}

/**
 * Creates a mock WriteStream that captures all written data.
 * Returns both the stream and a promise that resolves with the final buffer.
 */
export function createMockWriteStream(): { stream: WriteStream; getData: () => Promise<Buffer> } {
  const chunks: Buffer[] = []
  let resolveData: (data: Buffer) => void
  let rejectData: (error: Error) => void
  const dataPromise = new Promise<Buffer>((resolve, reject) => {
    resolveData = resolve
    rejectData = reject
  })

  const stream = new Writable({
    write(chunk: Buffer, encoding, callback) {
      chunks.push(chunk)
      callback()
    },
    final(callback) {
      const finalData = Buffer.concat(chunks)
      resolveData(finalData)
      callback()
    },
    destroy(error, callback) {
      if (error) {
        rejectData(error)
      } else if (chunks.length > 0) {
        const finalData = Buffer.concat(chunks)
        resolveData(finalData)
      }
      callback(error)
    },
  }) as unknown as WriteStream

  // Writable already has an end method, so we can use it directly
  // The cast to WriteStream is sufficient for the mock

  return {
    stream,
    getData: () => dataPromise,
  }
}

/**
 * Mock file system for testing.
 * Stores file contents in memory and provides mock implementations
 * of fs functions.
 */
export class MockFileSystem {
  private files: Map<string, Buffer> = new Map()

  /**
   * Creates a file with the given path and data
   */
  createFile(path: string, data: Buffer): void {
    this.files.set(path, data)
  }

  /**
   * Gets file data
   */
  getFile(path: string): Buffer | undefined {
    return this.files.get(path)
  }

  /**
   * Gets file size
   */
  getFileSize(path: string): number {
    const data = this.files.get(path)
    return data ? data.length : 0
  }

  /**
   * Checks if file exists
   */
  fileExists(path: string): boolean {
    return this.files.has(path)
  }

  /**
   * Clears all files
   */
  clear(): void {
    this.files.clear()
  }

  /**
   * Creates a mock statSync function
   */
  createStatSync() {
    return (path: string | Buffer) => {
      const pathString = typeof path === 'string' ? path : path.toString()
      const size = this.getFileSize(pathString)
      if (size === 0 && !this.fileExists(pathString)) {
        const error = new Error(`ENOENT: no such file or directory, stat '${pathString}'`) as NodeJS.ErrnoException
        error.code = 'ENOENT'
        error.errno = -2
        throw error
      }
      return { size }
    }
  }

  /**
   * Creates a mock createReadStream function
   */
  createReadStream(options?: { highWaterMark?: number }) {
    return (path: string | Buffer, streamOptions?: { start?: number; end?: number; highWaterMark?: number }) => {
      const pathString = typeof path === 'string' ? path : path.toString()
      const fileData = this.getFile(pathString)
      if (!fileData) {
        const error = new Error(`ENOENT: no such file or directory, open '${pathString}'`) as NodeJS.ErrnoException
        error.code = 'ENOENT'
        throw error
      }

      const start = streamOptions?.start ?? 0
      const end = streamOptions?.end ?? fileData.length - 1
      const highWaterMark = streamOptions?.highWaterMark ?? options?.highWaterMark ?? 64 * 1024

      // Extract the range
      const rangeData = fileData.subarray(start, end + 1)

      return createMockReadStream(rangeData, { highWaterMark })
    }
  }

  /**
   * Creates a mock createWriteStream function
   */
  createWriteStream() {
    return (path: string | Buffer) => {
      const pathString = typeof path === 'string' ? path : path.toString()
      const chunks: Buffer[] = []
      const files = this.files
      const stream = new Writable({
        write(chunk: Buffer, encoding, callback) {
          chunks.push(chunk)
          callback()
        },
        final(callback) {
          // Save data synchronously when final is called
          const finalData = Buffer.concat(chunks)
          files.set(pathString, finalData)
          callback()
        },
        destroy(error, callback) {
          // Save data even if destroyed (if we have chunks)
          if (chunks.length > 0 && !error) {
            const finalData = Buffer.concat(chunks)
            files.set(pathString, finalData)
          }
          callback(error)
        },
      }) as unknown as WriteStream

      return stream
    }
  }

  /**
   * Creates a mock fs.promises.open function
   */
  createOpen() {
    return (path: string | Buffer) => {
      const pathString = typeof path === 'string' ? path : path.toString()
      const fileData = this.getFile(pathString)
      if (!fileData) {
        const error = new Error(`ENOENT: no such file or directory, open '${pathString}'`) as NodeJS.ErrnoException
        error.code = 'ENOENT'
        return Promise.reject(error)
      }

      // Capture file data at open time to ensure consistency
      const snapshot = Buffer.from(fileData)

      return Promise.resolve({
        read: (buffer: Buffer, offset: number, length: number, position: number) => {
          if (position >= snapshot.length) {
            return Promise.resolve({ bytesRead: 0, buffer })
          }
          const end = Math.min(position + length, snapshot.length)
          const actualLength = end - position
          if (actualLength <= 0) {
            return Promise.resolve({ bytesRead: 0, buffer })
          }
          const sourceData = snapshot.subarray(position, end)
          sourceData.copy(buffer, offset)
          return Promise.resolve({ bytesRead: actualLength, buffer })
        },
        close: () => {
          // No-op for mock
          return Promise.resolve()
        },
      })
    }
  }
}
