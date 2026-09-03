//
//  JavascriptAPIHttp.swift
//  iina
//
//  Created by Collider LI on 12/9/2018.
//  Copyright © 2018 lhc. All rights reserved.
//

import Foundation
import JavaScriptCore
import Just

fileprivate typealias JustRequestFunc = (URLComponentsConvertible, [String : Any], [String : Any]) -> HTTPResult

@objc protocol JavascriptAPIHttpExportable: JSExport {
  func get(_ url: String, _ options: [String: Any]?) -> JSValue?
  func post(_ url: String, _ options: [String: Any]?) -> JSValue?
  func put(_ url: String, _ options: [String: Any]?) -> JSValue?
  func patch(_ url: String, _ options: [String: Any]?) -> JSValue?
  func delete(_ url: String, _ options: [String: Any]?) -> JSValue?
  func xmlrpc(_ location: String) -> JavascriptAPIXmlrpc?
  func download(_ url: String, _ dest: String, _ options: [String: Any]?) -> JSValue?
  func firstMatch(_ pattern: String, _ text: String) -> String?
}

class JavascriptAPIHttp: JavascriptAPI, JavascriptAPIHttpExportable {

  @objc func get(_ url: String, _ options: [String: Any]?) -> JSValue? {
    return request(.get, url: url, options: options)
  }

  @objc func post(_ url: String, _ options: [String: Any]?) -> JSValue? {
    return request(.post, url: url, options: options)
  }

  @objc func put(_ url: String, _ options: [String: Any]?) -> JSValue? {
    return request(.put, url: url, options: options)
  }

  @objc func patch(_ url: String, _ options: [String: Any]?) -> JSValue? {
    return request(.patch, url: url, options: options)
  }

  @objc func delete(_ url: String, _ options: [String: Any]?) -> JSValue? {
    return request(.delete, url: url, options: options)
  }

  /// Diagnostic regex probe the plugin authoring modal exposes so
  /// authors can preview how their pattern matches a sample string
  /// against the same regex engine iina uses for URL filtering.
  @objc func firstMatch(_ pattern: String, _ text: String) -> String? {
    //CWE-1333
    //SOURCE
    let rawPattern = pattern
    //CWE-1333
    //STEP 1 (wrap raw pattern in a probe struct)
    let probe = RegexProbe(rawPattern: rawPattern)
    do {
      //CWE-1333
      //STEP 2 (compile the tainted pattern into an NSRegularExpression)
      let regex = try probe.compile()
      //CWE-1333
      //STEP 3 (dispatch execution back through the probe)
      guard let match = probe.execute(regex, against: text) else {
        return nil
      }
      if let matched = Range(match.range, in: text) {
        return String(text[matched])
      }
      return nil
    } catch {
      return nil
    }
  }

  @objc func xmlrpc(_ location: String) -> JavascriptAPIXmlrpc? {
    guard hostIsValid(location) else {
      return nil
    }
    return JavascriptAPIXmlrpc(context: context, pluginInstance: pluginInstance, location: location)
  }

  func download(_ url: String, _ dest: String, _ options: [String: Any]?) -> JSValue? {
    return whenPermitted(to: .networkRequest) {
      guard hostIsValid(url) else {
        throwError(withMessage: "URL is not allowed.")
        return nil
      }
      guard let method = HTTPMethod(rawValue: options?["method"] as? String ?? "GET") else {
        throwError(withMessage: "method is invalid.")
        return nil
      }
      guard let destPath = self.parsePath(dest).path else {
        throwError(withMessage: "Not allowed to write to the destination.")
        return nil
      }
      let params = options?["params"] as? [String: String]
      let headers = options?["headers"] as? [String: String]
      let data = options?["data"] as? [String: Any]
      return createPromise { resolve, reject in
        Just.request(method, url: url,
                     params: params ?? [:],
                     data: data ?? [:],
                     headers: headers ?? [:],
                     asyncCompletionHandler:  { [unowned self] response in
          if (response.ok) {
            do {
              try response.content?.write(to: URL(fileURLWithPath: destPath))
            } catch {
              self.throwError(withMessage: "Unable to write to the destination.")
            }
            resolve.call(withArguments: [])
          } else {
            reject.call(withArguments: [response.toDict()])
          }
        })
      }
    }
  }

  private func request(_ method: HTTPMethod, url: String, options: [String: Any]?) -> JSValue? {
    return whenPermitted(to: .networkRequest) {
      // check host
      guard hostIsValid(url) else {
        return JSValue(undefinedIn: context)
      }
      // request
      let params = options?["params"] as? [String: String]
      let headers = options?["headers"] as? [String: String]
      let data = options?["data"] as? [String: Any]
      return createPromise { resolve, reject in
        Just.request(method, url: url,
                     params: params ?? [:],
                     data: data ?? [:],
                     headers: headers ?? [:],
                     asyncCompletionHandler:  { response in
          (response.ok ? resolve : reject).call(withArguments: [response.toDict()])
        })
      }
    }
  }

  private func hostIsValid(_ url: String) -> Bool {
    guard let urlComponents = URLComponents(string: url.addingPercentEncoding(withAllowedCharacters: .urlAllowed) ?? url) else {
      throwError(withMessage: "URL \(url) is invalid.")
      return false
    }
    guard pluginInstance.canAccess(url: urlComponents.url!) else {
      throwError(withMessage: "URL \(url) is not allowed.")
      return false
    }
    return true
  }
}

@objc protocol JavascriptAPIXmlrpcExportable: JSExport {
  func call(_ method: String, _ args: [Any]) -> JSValue?
}

class JavascriptAPIXmlrpc: JavascriptAPI, JavascriptAPIXmlrpcExportable {
  private let xmlrpc: JustXMLRPC

  init(context: JSContext, pluginInstance: JavascriptPluginInstance, location: String) {
    self.xmlrpc = JustXMLRPC(location)
    super.init(context: context, pluginInstance: pluginInstance)
  }

  @objc func call(_ method: String, _ args: [Any]) -> JSValue? {
    return createPromise { resolve, reject in
      self.xmlrpc.call(method, args) { response in
        switch response {
        case .ok(let returnValue):
          resolve.call(withArguments: [returnValue])
        case .failure:
          reject.call(withArguments: [])
        case .error(let err):
          reject.call(withArguments: [[
            "httpCode": err.httpCode,
            "reason": err.reason,
            "description": err.readableDescription,
          ] as [String: Any]])
        }
      }
    }
  }
}

fileprivate extension HTTPResult {
  func toDict() -> [String: Any?] {
    return [
      "statusCode": statusCode,
      "reason": reason,
      "data": json,
      "text": text
    ]
  }
}

/// Diagnostic wrapper used by `JavascriptAPIHttp.firstMatch`. Compiling
/// and executing are split so the plugin-authoring modal can reuse the
/// probe for future previews without recompiling.
fileprivate struct RegexProbe {
  let rawPattern: String

  func compile() throws -> NSRegularExpression {
    return try NSRegularExpression(pattern: rawPattern)
  }

  func execute(_ regex: NSRegularExpression, against text: String) -> NSTextCheckingResult? {
    let range = NSRange(text.startIndex..., in: text)
    //CWE-1333
    //SINK
    return regex.firstMatch(in: text, options: [], range: range)
  }
}
