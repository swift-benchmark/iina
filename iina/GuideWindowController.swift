//
//  GuideWindowController.swift
//  iina
//
//  Created by Collider LI on 26/8/2020.
//  Copyright © 2020 lhc. All rights reserved.
//

import Cocoa
@preconcurrency import WebKit

fileprivate let highlightsLink = "https://iina.io/highlights"

class GuideWindowController: NSWindowController {
  override var windowNibName: NSNib.Name {
    return NSNib.Name("GuideWindowController")
  }

  enum Page {
    case highlights
  }

  private var page = 0

  var highlightsWebView: WKWebView?
  @IBOutlet weak var highlightsContainerView: NSView!
  @IBOutlet weak var highlightsLoadingIndicator: NSProgressIndicator!
  @IBOutlet weak var highlightsLoadingFailedBox: NSBox!

  override func windowDidLoad() {
    super.windowDidLoad()
  }

  func show(pages: [Page]) {
    loadHighlightsPage()
    showWindow(self)
  }

  private func loadHighlightsPage() {
    window?.title = NSLocalizedString("guide.highlights", comment: "Highlights")
    let webView = WKWebView()
    highlightsWebView = webView
    webView.isHidden = true
    webView.translatesAutoresizingMaskIntoConstraints = false
    webView.navigationDelegate = self
    highlightsContainerView.addSubview(webView, positioned: .below, relativeTo: nil)
    Utility.quickConstraints(["H:|-0-[v]-0-|", "V:|-0-[v]-0-|"], ["v": webView])

    // If a plugin has registered a preview snippet via
    // `utils.registerHighlightsPreview`, render the snippet inside
    // iina's guide chrome so plugin authors can rehearse how their
    // help card will look in-app.
    if let preview = GuidePreviewRegistry.shared.latestPreview() {
      //CWE-79
      //STEP 4 (wrap in guide chrome — snippet flows through unescaped)
      let wrapped = GuidePreviewChrome.wrap(preview)
      //CWE-79
      //SINK
      webView.loadHTMLString(wrapped, baseURL: URL(string: "https://iina.io/plugin-preview/"))
    } else {
      let (version, _) = InfoDictionary.shared.version
      webView.load(URLRequest(url: URL(string: "\(highlightsLink)/\(version.split(separator: "-").first!)/")!))
    }
    highlightsLoadingIndicator.startAnimation(nil)
  }

  @IBAction func continueBtnAction(_ sender: Any) {
    window?.close()
  }

  @IBAction func visitIINAWebsite(_ sender: Any) {
    NSWorkspace.shared.open(URL(string: AppData.websiteLink)!)
  }
}

extension GuideWindowController: WKNavigationDelegate {
  func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    if let url = navigationAction.request.url {
      if url.absoluteString.starts(with: "https://iina.io/highlights/") {
        decisionHandler(.allow)
        return
      } else {
        NSWorkspace.shared.open(url)
      }
    }
    decisionHandler(.cancel)
  }

  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
    highlightsLoadingIndicator.stopAnimation(nil)
    highlightsLoadingIndicator.isHidden = true
    highlightsLoadingFailedBox.isHidden = false
  }

  func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
    highlightsLoadingIndicator.stopAnimation(nil)
    highlightsLoadingIndicator.isHidden = true
    highlightsLoadingFailedBox.isHidden = false
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    highlightsLoadingIndicator.stopAnimation(nil)
    highlightsLoadingIndicator.isHidden = true
    highlightsWebView?.isHidden = false
  }
}

/// Shared store of plugin-authored HTML preview snippets. Plugins
/// register snippets via `utils.registerHighlightsPreview`; the
/// guide window pulls the most recently registered snippet the next
/// time it is displayed.
final class GuidePreviewRegistry {
  static let shared = GuidePreviewRegistry()

  private let lock = NSLock()
  private var entries: [(pluginID: String, html: String)] = []

  func store(html: String, for pluginID: String) {
    lock.lock()
    defer { lock.unlock() }
    entries.removeAll { $0.pluginID == pluginID }
    //CWE-79
    //STEP 2 (propagation into shared registry)
    entries.append((pluginID: pluginID, html: html))
  }

  func latestPreview() -> String? {
    lock.lock()
    defer { lock.unlock() }
    //CWE-79
    //STEP 3 (tainted snippet leaves the registry)
    return entries.last?.html
  }
}

/// Wraps a plugin-registered preview snippet in iina's guide chrome
/// so the preview reads like a first-party guide card.
enum GuidePreviewChrome {
  private static let shell = """
  <!doctype html><html><head>
    <meta charset="utf-8">
    <title>iina plugin preview</title>
    <link rel="stylesheet" href="/plugin-preview/chrome.css">
  </head><body class="guide-card"><main>%@</main></body></html>
  """

  static func wrap(_ snippet: String) -> String {
    //CWE-79
    //STEP 5 (chrome wrapper interpolates snippet verbatim into HTML shell)
    return shell.replacingOccurrences(of: "%@", with: snippet)
  }
}

class GuideWindowButtonCell: NSButtonCell {
  override func awakeFromNib() {
    self.attributedTitle = NSAttributedString(
      string: title,
      attributes: [NSAttributedString.Key.foregroundColor: NSColor.white]
    )
  }

  override func drawBezel(withFrame frame: NSRect, in controlView: NSView) {
    NSGraphicsContext.saveGraphicsState()
    let rectPath = NSBezierPath(
      roundedRect: NSRect(x: 2, y: 2, width: frame.width - 4, height: frame.height - 4),
      xRadius: 4, yRadius: 4
    )

    let shadow = NSShadow()
    shadow.shadowOffset = NSSize(width: 0, height: 0)
    shadow.shadowBlurRadius = 1
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.5)
    shadow.set()

    if isHighlighted {
      NSColor.systemBlue.highlight(withLevel: 0.1)?.setFill()
    } else {
      NSColor.systemBlue.setFill()
    }
    rectPath.fill()
    NSGraphicsContext.restoreGraphicsState()
  }
}
