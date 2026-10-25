import SwiftUI
import AppKit
import CoreImage.CIFilterBuiltins
import UniformTypeIdentifiers
import DazzleModels
import DazzleTransport

struct ExportView: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: AppStore
    let artifact: ExportArtifact
    @State private var selected: ExportSelection
    @State private var saveFormat = "file"
    @State private var reveal = false
    init(store: AppStore, artifact: ExportArtifact) {
        self.store = store; self.artifact = artifact
        _selected = State(initialValue: artifact.defaultSelection)
    }
    private var address: String? { artifact.address(for: selected) }
    private var qr: NSImage? {
        guard let address, address.utf8.count <= 2900 else { return nil }
        let filter = CIFilter.qrCodeGenerator(); filter.message = Data(address.utf8); filter.correctionLevel = "M"
        guard let image = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(image, from: image.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: image.extent.width, height: image.extent.height))
    }
    private var fileFormat: String { artifact.clientTitle }
    var body: some View {
        VStack(spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text(artifact.clientTitle).font(.title2.weight(.semibold)).foregroundStyle(VPSTheme.ink)
                    Label("私密 · 仅向对应授权用户提供", systemImage: "lock.fill").font(.caption).foregroundStyle(VPSTheme.muted)
                }
                Spacer(); Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            Group {
                Label("真实新入口 · " + WorkerState.label(artifact.runtimeState), systemImage: "server.rack")
                    .font(.caption).foregroundStyle(VPSTheme.accent).frame(maxWidth: .infinity)
            }
            Picker("二维码与链接", selection: $selected) {
                ForEach(artifact.selections, id: \.self) { option in Text(artifact.label(for: option)).tag(option) }
            }.pickerStyle(.segmented)
            Group {
                if let qr {
                    Image(nsImage: qr).interpolation(.none).resizable().scaledToFit()
                        .frame(width: 264, height: 264).padding(14).background(.white, in: RoundedRectangle(cornerRadius: 16))
                } else {
                    VStack(spacing: 12) { Image(systemName: "qrcode").font(.system(size: 74, weight: .ultraLight)); Text("暂无可用二维码").font(.caption) }
                        .foregroundStyle(VPSTheme.muted).frame(width: 292, height: 292)
                }
            }
            HStack(spacing: 8) {
                Image(systemName: address == nil ? "cloud" : "qrcode.viewfinder")
                Text(address == nil ? "此链接尚未就绪 · 可保存配置文件" : selected == .subscription ? "导入“" + artifact.label(for: selected) + "”链接" : selected == .rules ? "在 Shadowrocket 配置页导入规则" : "使用客户端扫描或导入节点")
            }.font(.caption).foregroundStyle(VPSTheme.muted)
            Divider()
            HStack(spacing: 12) {
                Picker("保存为", selection: $saveFormat) { Text(fileFormat).tag("file"); Text("PNG 二维码").tag("qr") }.frame(maxWidth: .infinity)
                Button(selected == .vless || selected == .tuic ? "复制节点" : "复制" + artifact.label(for: selected)) { if let address { store.copyPrivate(address) } }
                    .disabled(address == nil).help("60秒后清除未变化的剪贴板")
                Button("保存…") { if saveFormat == "qr" { saveQR() } else { store.saveArtifact(artifact) } }
                    .buttonStyle(.borderedProminent).disabled(saveFormat == "qr" && qr == nil)
            }
            DisclosureGroup(isExpanded: $reveal) {
                ScrollView { Text(artifact.content).font(.system(size: 10, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    .frame(height: 105).padding(10).background(VPSTheme.ink.opacity(0.035), in: RoundedRectangle(cornerRadius: 8))
            } label: {
                HStack { Text("查看配置正文"); Spacer(); Text("文件权限 0600").foregroundStyle(VPSTheme.muted) }
            }.font(.caption).frame(maxWidth: .infinity, alignment: .leading)
        }.padding(26).frame(width: 570)
    }
    private func saveQR() {
        guard let qr, let tiff = qr.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff), let png = rep.representation(using: .png, properties: [:]) else { return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = "Dazzle-\(selected.rawValue.uppercased()).png"; panel.allowedContentTypes = [.png]; panel.title = "保存私密二维码"
        if panel.runModal() == .OK, let url = panel.url {
            do { try SecureExport.write(png, to: url); store.notice = "已保存私密二维码。" }
            catch { store.error = error.localizedDescription }
        }
    }
}
