import SwiftUI
import AppKit
import DazzleModels

enum VPSTheme {
    static let accent = Color(red: 0.08, green: 0.49, blue: 0.42)
    static let blue = Color(red: 0.28, green: 0.51, blue: 0.86)
    static let ink = Color.primary
    static let muted = Color.secondary
    static let canvas = Color(nsColor: .windowBackgroundColor)
    static let surface = Color(nsColor: .controlBackgroundColor)
    static let line = Color.primary.opacity(0.07)
}

struct Card<Content: View>: View {
    var title: String?
    @ViewBuilder var content: Content
    init(_ title: String? = nil, @ViewBuilder content: () -> Content) { self.title = title; self.content = content() }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let title { Text(title).font(.system(size: 14, weight: .semibold)) }
            content
        }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(VPSTheme.surface, in: RoundedRectangle(cornerRadius: 18))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(VPSTheme.line, lineWidth: 1))
    }
}
struct NoticeBox: View {
    let icon: String; let text: String; var tint: Color = .teal
    var body: some View {
        Label(text, systemImage: icon).font(.system(size: 12)).foregroundStyle(tint)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading).padding(11)
            .background(tint.opacity(0.065), in: RoundedRectangle(cornerRadius: 10))
    }
}
struct MetricCard: View {
    let title: String; let value: String; let note: String; let icon: String
    var body: some View {
        Card {
            Label(title, systemImage: icon).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(size: 26, weight: .semibold, design: .rounded)).minimumScaleFactor(0.6).lineLimit(1)
            Text(note).font(.caption2).foregroundStyle(.secondary)
        }
    }
}
struct ValueRow: View {
    let name: String; let value: String
    var body: some View {
        HStack(alignment: .top) { Text(name).foregroundStyle(.secondary); Spacer(minLength: 16); Text(value).multilineTextAlignment(.trailing).textSelection(.enabled) }.font(.system(size: 12))
    }
}
struct EmptyState: View {
    let icon: String; let title: String; let detail: String
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 28, weight: .light)).foregroundStyle(VPSTheme.accent.opacity(0.7))
            Text(title).font(.headline)
            if !detail.isEmpty { Text(detail).font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 350) }
        }.frame(maxWidth: .infinity).padding(.vertical, 26)
    }
}
struct UsageTrack: View {
    let used: Int64
    let limit: Int64?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private var fraction: Double { ChartValues.fraction(used: used, limit: limit) ?? 0 }
    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.primary.opacity(0.055))
                if limit != nil && fraction > 0 {
                    Capsule().fill(used >= (limit ?? 0) ? Color.orange : VPSTheme.accent)
                        .frame(width: proxy.size.width * fraction)
                }
            }
        }.frame(height: 6)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.25), value: fraction)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(limit == nil ? "不设个人额度" : "已用 \(Display.bytes(used))，额度 \(Display.bytes(limit))")
    }
}
struct PayloadRing: View {
    let upload: Int64; let download: Int64
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private var total: Int64 { TrafficOverview.sum([upload, download]) }
    private var split: Double { total > 0 ? Double(upload) / Double(total) : 0 }
    var body: some View {
        ZStack {
            Circle().stroke(Color.primary.opacity(0.055), lineWidth: 14)
            if total > 0 {
                Circle().trim(from: 0, to: split).stroke(VPSTheme.accent, style: StrokeStyle(lineWidth: 14, lineCap: .butt)).rotationEffect(.degrees(-90))
                Circle().trim(from: split, to: 1).stroke(VPSTheme.blue, style: StrokeStyle(lineWidth: 14, lineCap: .butt)).rotationEffect(.degrees(-90))
            }
            VStack(spacing: 5) {
                Text(Display.bytes(total)).font(.system(size: 28, weight: .semibold, design: .rounded)).minimumScaleFactor(0.55).lineLimit(1)
                Text("本期代理用量").font(.system(size: 11)).foregroundStyle(.secondary)
            }.padding(16)
        }.frame(width: 168, height: 168)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.3), value: split)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("本期代理用量 \(Display.bytes(total))，上传 \(Display.bytes(upload))，下载 \(Display.bytes(download))")
    }
}
struct IconTile: View {
    let symbol: String
    var tint: Color = VPSTheme.accent
    var body: some View { Image(systemName: symbol).font(.system(size: 15, weight: .medium)).foregroundStyle(tint).frame(width: 34, height: 34).background(tint.opacity(0.085), in: RoundedRectangle(cornerRadius: 10)) }
}

enum UIFormat {
    static func date(_ value: JSONValue, format: String, zone: String = "Asia/Shanghai") -> String {
        guard let date = ChartValues.date(value) else { return "未设置" }
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "zh_CN"); formatter.timeZone = TimeZone(identifier: zone); formatter.dateFormat = format
        return formatter.string(from: date)
    }
    static func upcoming(_ value: JSONValue) -> String {
        guard let date = ChartValues.date(value) else { return "等待设置" }
        let seconds = date.timeIntervalSinceNow
        return seconds <= 0 ? "等待处理" : seconds < 86400 ? "24 小时内" : "\(Int(ceil(seconds / 86400))) 天后"
    }
}
