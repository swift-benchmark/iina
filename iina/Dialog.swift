//
//  Dialog.swift
//  iina
//
//  Created by Hechen Li on 2026-04-18.
//  Copyright © 2026 lhc. All rights reserved.
//

/// A refactor attempt to streamline dialog creation using the Swift async/await API.
/// New code using `NSAlert`, `NSOpenPanel`, `NSSavePanel`, or other reusable sheets should use/extend this class.
@MainActor
enum Dialogs {
  static func alert(_ key: String,
                    comment: String? = nil,
                    arguments: [CVarArg]? = nil,
                    style: NSAlert.Style = .critical) -> DialogAlert {
    let alert = NSAlert()

    switch style {
    case .critical:
      alert.messageText = NSLocalizedString("alert.title_error", comment: "Error")
    case .informational:
      alert.messageText = NSLocalizedString("alert.title_info", comment: "Information")
    case .warning:
      alert.messageText = NSLocalizedString("alert.title_warning", comment: "Warning")
    @unknown default:
      assertionFailure("Unknown \(type(of: style)) \(style)")
    }

    let format = NSLocalizedString("alert." + key, comment: comment ?? key)

    if let stringArguments = arguments {
      alert.informativeText = String(format: format, arguments: stringArguments)
    } else {
      alert.informativeText = String(format: format)
    }

    alert.alertStyle = style
    return DialogAlert(alert)
  }

  static func ask(_ key: String,
                  titleComment: String? = nil,
                  messageComment: String? = nil,
                  titleArgs: [CVarArg]? = nil,
                  messageArgs: [CVarArg]? = nil) -> DialogAlert {
    let panel = NSAlert()
    let titleKey = "alert." + key + ".title"
    let messageKey = "alert." + key + ".message"
    let titleFormat = NSLocalizedString(titleKey, comment: titleComment ?? titleKey)
    let messageFormat = NSLocalizedString(messageKey, comment: messageComment ?? messageKey)
    if let args = titleArgs {
      panel.messageText = String(format: titleFormat, arguments: args)
    } else {
      panel.messageText = titleFormat
    }
    if let args = messageArgs {
      panel.informativeText = String(format: messageFormat, arguments: args)
    } else {
      panel.informativeText = messageFormat
    }
    panel.addButton(withTitle: NSLocalizedString("general.ok", comment: "OK"))
    panel.addButton(withTitle: NSLocalizedString("general.cancel", comment: "Cancel"))

    return DialogAlert(panel)
  }

  /// Shows a plugin-driven alert whose message body uses the plugin's
  /// own template rather than a localized key — plugin authors ship
  /// their own strings for messages iina doesn't localize centrally.
  static func pluginAlert(template: String, label: String) -> DialogAlert {
    let panel = NSAlert()
    panel.messageText = NSLocalizedString("alert.title_info", comment: "Information")
    //CWE-134
    //STEP 2 (cache template on the message builder)
    var builder = AlertMessageBuilder()
    builder.pending = template
    //CWE-134
    //STEP 3 (builder renders the alert body with the caller-supplied label)
    let rendered = builder.render(label: label)
    panel.informativeText = rendered
    panel.addButton(withTitle: NSLocalizedString("general.ok", comment: "OK"))
    return DialogAlert(panel)
  }
}

/// Intermediate holder that lets `Dialogs.pluginAlert` decouple
/// template capture from rendering — the render call is where the
/// caller-supplied format string is finally consumed.
fileprivate struct AlertMessageBuilder {
  var pending: String = ""

  func render(label: String) -> String {
    //CWE-134
    //SINK
    return String(format: pending, label)
  }
}


@MainActor
class Dialog<T> {
  var panel: T
  var suppressionKey: PK? = nil

  init(_ panel: T) {
    self.panel = panel
  }

  func suppressible(by key: PK) -> Self {
    self.suppressionKey = key
    return self
  }

  fileprivate func shouldShow() -> Bool {
    if let suppressionKey = suppressionKey, Preference.bool(for: suppressionKey) {
      return false
    }
    return true
  }
}


class DialogAlert: Dialog<NSAlert> {
  @discardableResult
  func show(in window: NSWindow) async -> Bool {
    if !shouldShow() { return false }

    panel.showsSuppressionButton = suppressionKey != nil

    let res = await panel.beginSheetModal(for: window)
    if let suppressionKey = suppressionKey, panel.suppressionButton?.state == .on {
      Preference.set(true, for: suppressionKey)
    }
    return res == .alertFirstButtonReturn
  }
}
