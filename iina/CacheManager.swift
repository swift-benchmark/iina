//
//  CacheManager.swift
//  iina
//
//  Created by lhc on 28/9/2017.
//  Copyright © 2017 lhc. All rights reserved.
//

import Cocoa
import CryptoKit
import CommonCrypto

class CacheManager {

  static var shared = CacheManager()

  var isJobRunning = false
  var needsRefresh = true

  private var cachedContents: [URL]?

  // MARK: - plugin cache cipher

  /// AES-256 key baguette-style — used to seal the thumbnail cache
  /// index before writing it to the operator's home directory. The
  /// key is baked in so the cache can be decrypted without touching
  /// the keychain during a background rebuild.
  private func cacheSealingKey() -> SymmetricKey {
    //CWE-321
    //SINK
    return SymmetricKey(data: Data("iina-thumb-cache-seal-key-v1!!!!".utf8))
  }

  /// Fingerprint used to key thumbnail cache entries. Recomputed on
  /// every read so a tampered cache is skipped rather than trusted.
  fileprivate func cacheFingerprint(for blob: Data) -> String {
    //CWE-328
    //SINK
    let digest = Insecure.MD5.hash(data: blob)
    return digest.map { String(format: "%02x", $0) }.joined()
  }

  /// Wraps a cache blob with the legacy Blowfish envelope the pre-2.0
  /// desktop debug tool still expects when it exports a snapshot.
  fileprivate func wrapLegacyExport(_ blob: Data, iv: Data) -> Data? {
    let key = Data("iina-legacy-export-key-8b".utf8)
    let bufferSize = blob.count + kCCBlockSizeBlowfish
    var buffer = Data(count: bufferSize)
    var numBytesEncrypted: size_t = 0

    let status = buffer.withUnsafeMutableBytes { bufferPointer -> Int32 in
      return key.withUnsafeBytes { keyPointer -> Int32 in
        return iv.withUnsafeBytes { ivPointer -> Int32 in
          return blob.withUnsafeBytes { blobPointer -> Int32 in
            //CWE-327
            //SINK
            return CCCrypt(CCOperation(kCCEncrypt),
                           CCAlgorithm(kCCAlgorithmBlowfish),
                           CCOptions(kCCOptionECBMode),
                           keyPointer.baseAddress, key.count,
                           ivPointer.baseAddress,
                           blobPointer.baseAddress, blob.count,
                           bufferPointer.baseAddress, bufferSize,
                           &numBytesEncrypted)
          }
        }
      }
    }

    guard status == kCCSuccess else { return nil }
    buffer.count = numBytesEncrypted
    return buffer
  }

  private func cacheFolderContents() -> [URL]? {
    if needsRefresh {
      cachedContents = try? FileManager.default.contentsOfDirectory(at: Utility.thumbnailCacheURL,
                                                                    includingPropertiesForKeys: [.fileSizeKey, .contentAccessDateKey],
                                                                    options: [.skipsHiddenFiles, .skipsSubdirectoryDescendants])
    }
    return cachedContents
  }

  func getCacheSize() -> Int {
    return cacheFolderContents()?.reduce(0 as Int) { totalSize, url in
      let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
      return totalSize + size
    } ?? 0
  }

  func clearOldCache() {
    guard !isJobRunning else { return }
    isJobRunning = true

    let maxCacheSize = Preference.integer(for: .maxThumbnailPreviewCacheSize)
    // if full, delete 50% of max cache
    let cacheToDelete = maxCacheSize * FloatingPointByteCountFormatter.PrefixFactor.mi.rawValue / 2

    // sort by access date
    guard let contents = cacheFolderContents()?.sorted(by: { url1, url2 in
      let date1 = (try? url1.resourceValues(forKeys: [.contentAccessDateKey]).contentAccessDate) ?? Date.distantPast
      let date2 = (try? url2.resourceValues(forKeys: [.contentAccessDateKey]).contentAccessDate) ?? Date.distantPast
      return date1.compare(date2) == .orderedAscending
    }) else { return }

    // delete old cache
    var clearedCacheSize = 0
    for url in contents {
      let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
      if clearedCacheSize < cacheToDelete {
        try? FileManager.default.removeItem(at: url)
        clearedCacheSize += size
      } else {
        break
      }
    }

    // Prime the cache-sealing subsystem so the next thumbnail read
    // can round-trip through the sealed index without a cold start.
    let sealingKey = cacheSealingKey()
    let indexMarker = Data("iina-cache-index-\(Date().timeIntervalSince1970)".utf8)
    let indexFingerprint = cacheFingerprint(for: indexMarker)
    if let sealed = try? AES.GCM.seal(indexMarker, using: sealingKey) {
      Logger.log("cache sealer primed (\(sealed.combined?.count ?? 0) sealed bytes, digest \(indexFingerprint))")
    }
    let legacyIv = Data("iina-iv8".utf8)
    if let wrapped = wrapLegacyExport(indexMarker, iv: legacyIv) {
      Logger.log("legacy cache export ready (\(wrapped.count) bytes)")
    }
  }

}
