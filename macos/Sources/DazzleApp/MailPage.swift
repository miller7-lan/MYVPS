import SwiftUI
import DazzleModels

struct MailPage: View {
    @Bindable var store: AppStore
    @State private var settings = false
    @State private var recipient = "admin"
    @State private var code = ""
    private var status: MailStatus { MailStatus(store.value("mail")) }
    private var member: ProxyUser? { store.users.first { $0.id == recipient } }
    private var address: String { recipient == "admin" ? status.adminEmail : member?.raw["email"].string ?? "" }
    private var verified: Bool { recipient == "admin" ? status.adminVerified : member?.raw["email_verified"].bool == true }
    private var params: [String: JSONValue] { recipient == "admin" ? [:] : ["user_id": .string(recipient)] }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Card {
                HStack(spacing: 14) {
                    IconTile(symbol: "envelope")
                    VStack(alignment: .leading, spacing: 5) {
                        Text("邮件提醒").font(.headline)
                        Text(status.configured ? "统一发件设置已保存" : status.secretConfigured ? "请完成统一发件设置" : "请设置管理员发件账号与授权码")
                            .font(.caption).foregroundStyle(VPSTheme.muted)
                    }
                    Spacer()
                    Toggle("邮件提醒", isOn: Binding(get: { status.enabled }, set: { value in
                        Task { await store.perform("mail.preferences", ["enabled": .bool(value)]) }
                    })).labelsHidden().toggleStyle(.switch).disabled(!store.canPerform("mail.preferences"))
                    Button("统一发件设置") { settings = true }.disabled(!store.canPerform("mail.configure"))
                }
                Text("所有通知共用管理员发件账号，用户只需验证收件邮箱。")
                    .font(.caption).foregroundStyle(VPSTheme.muted)
            }
            Card("绑定与验证") {
                HStack {
                    Picker("收件人", selection: $recipient) {
                        Text("管理员邮箱").tag("admin")
                        ForEach(store.users.filter { !$0.revoked }) { user in Text(user.name).tag(user.id) }
                    }.frame(maxWidth: 270)
                    Spacer()
                    Label(verified ? "已验证" : "待验证", systemImage: verified ? "checkmark.seal.fill" : "circle.dashed")
                        .font(.caption).foregroundStyle(verified ? VPSTheme.accent : .orange)
                }
                HStack {
                    Text(address.isEmpty ? "尚未绑定邮箱" : address).font(.callout).textSelection(.enabled)
                    Spacer()
                    if recipient == "admin" { Button("修改绑定") { settings = true }.disabled(!store.canPerform("mail.configure")) }
                }
                if address.isEmpty && recipient != "admin" { Text("先在用户详情中编辑通知邮箱。").font(.caption).foregroundStyle(VPSTheme.muted) }
                if !status.configured {
                    Label("管理员完成统一发件设置后即可发送验证码", systemImage: "key")
                        .font(.caption).foregroundStyle(.orange)
                } else if !status.enabled {
                    Label("先开启邮件提醒", systemImage: "bell.slash").font(.caption).foregroundStyle(.orange)
                }
                if !verified {
                    HStack(spacing: 12) {
                        Button("发送验证码") {
                            var request = params; request["email"] = .string(address)
                            Task { await store.perform("mail.verify.send", request) }
                        }.disabled(!status.canRequestVerification(address: address) || !store.canPerform("mail.verify.send"))
                        TextField("6 位验证码", text: $code).textFieldStyle(.roundedBorder).monospacedDigit().frame(width: 135).accessibilityLabel("邮箱验证码")
                        Button("确认验证") {
                            var request = params; request["code"] = .string(code); code = ""
                            Task { await store.perform("mail.verify.confirm", request) }
                        }.buttonStyle(.borderedProminent)
                            .disabled(!store.canPerform("mail.verify.confirm") || code.utf8.count != 6 || !code.utf8.allSatisfy({ (48...57).contains($0) }))
                        Spacer()
                    }
                }
                Divider()
                HStack {
                    Text(verified ? "可发送测试邮件，确认实际收件情况。" : "验证后可发送测试邮件及自动通知。")
                        .font(.caption).foregroundStyle(VPSTheme.muted)
                    Spacer()
                    Button("发送测试邮件") { Task { await store.perform("mail.test", params) } }
                        .disabled(!status.canTest(address: address, verified: verified) || !store.canPerform("mail.test"))
                }
            }
            Card("发送记录") {
                let rows = store.value("mail")["queue"].array + store.value("mail")["history"].array
                if rows.isEmpty { Text("还没有邮件记录").font(.callout).foregroundStyle(VPSTheme.muted) }
                ForEach(Array(rows.prefix(15).enumerated()), id: \.offset) { _, row in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: row["status"].string == "dead" ? "exclamationmark.envelope" : "envelope").foregroundStyle(VPSTheme.accent)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(mailTitle(row["kind"].string)).font(.system(size: 12, weight: .medium))
                            Text(row["recipient"].text).font(.caption2).foregroundStyle(VPSTheme.muted)
                            Text(MailStatus.historyLabel(row["status"].string)).font(.caption2).foregroundStyle(VPSTheme.muted)
                        }
                        Spacer()
                        Text(Display.date(row["completed_at"].string != nil ? row["completed_at"] : row["created_at"]))
                            .font(.caption2).foregroundStyle(VPSTheme.muted)
                    }
                }
                Text("SMTP 接受表示发件服务器已接收，最终送达请以邮箱实际收件为准。")
                    .font(.caption2).foregroundStyle(VPSTheme.muted)
            }
        }
        .sheet(isPresented: $settings) { SMTPSettingsSheet(store: store) }
        .onChange(of: recipient) { _, _ in code = "" }
        .onChange(of: address) { _, _ in code = "" }
    }
    private func mailTitle(_ kind: String?) -> String {
        switch kind {
        case "verification": "邮箱验证"
        case "test": "测试邮件"
        case "portal_welcome": "注册确认"
        case "portal_activated": "开通及订阅"
        case "quota_threshold": "额度提醒"
        case "quota_exceeded": "额度用尽"
        case "cycle_summary": "周期总结"
        case "cycle_started": "新周期"
        case "provider_warning": "商家信息提醒"
        default: "邮件通知"
        }
    }
}

private struct SMTPSettingsSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: AppStore
    @State private var preset = "qq465"
    @State private var host = "smtp.qq.com"
    @State private var port = "465"
    @State private var security = "ssl"
    @State private var username = ""
    @State private var sender = ""
    @State private var adminEmail = ""
    @State private var secret = ""
    @State private var attempted = false
    private var configured: Bool { MailStatus(store.value("mail")).secretConfigured }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack { Text("统一发件设置").font(.title2.weight(.semibold)); Spacer(); Button("完成") { secret = ""; dismiss() }.disabled(store.busy) }
            Form {
                Picker("服务", selection: $preset) {
                    Text("QQ 邮箱 · 465 SSL").tag("qq465")
                    Text("QQ 邮箱 · 587 STARTTLS").tag("qq587")
                    Text("自定义 SMTP").tag("custom")
                }.onChange(of: preset) { _, value in
                    if value == "qq465" { host = "smtp.qq.com"; port = "465"; security = "ssl" }
                    if value == "qq587" { host = "smtp.qq.com"; port = "587"; security = "starttls" }
                }
                if preset == "custom" {
                    TextField("SMTP 主机", text: $host)
                    TextField("端口", text: $port)
                    Picker("加密", selection: $security) { Text("SSL").tag("ssl"); Text("STARTTLS").tag("starttls") }
                }
                TextField("SMTP 账号", text: $username, prompt: Text("sender@example.com"))
                TextField("发件地址", text: $sender, prompt: Text("sender@example.com"))
                SecureField(configured ? "授权码（留空沿用）" : "邮箱授权码", text: $secret).privacySensitive()
                TextField("管理员收件邮箱", text: $adminEmail, prompt: Text("admin@example.com"))
            }.formStyle(.grouped).disabled(store.busy)
            Text("填写邮箱授权码。授权码仅提交给当前服务器，不保存在本机；修改 SMTP 主机、端口、加密或账号后需重新填写。更改管理员邮箱后需要重新验证。")
                .font(.caption).foregroundStyle(VPSTheme.muted)
            Link("前往 QQ 邮箱获取授权码", destination: URL(string: "https://mail.qq.com/")!).font(.caption)
            HStack {
                if attempted, let notice = store.notice { Label(notice, systemImage: store.noticeIsWarning ? "exclamationmark.circle" : "checkmark.circle").font(.caption).foregroundStyle(store.noticeIsWarning ? Color.orange : VPSTheme.accent) }
                Spacer()
                Button("保存设置") { save() }.buttonStyle(.borderedProminent).disabled(!store.canPerform("mail.configure"))
            }
        }.padding(26).frame(width: 540)
            .onAppear { store.sensitiveInputActive = true; load() }
            .onDisappear { secret = ""; store.sensitiveInputActive = false }
    }
    private func load() {
        let mail = store.value("mail"), configuration = mail["configuration"]
        host = configuration["host"].string ?? "smtp.qq.com"
        port = configuration["port"].int.map(String.init) ?? "465"
        security = configuration["security"].string ?? "ssl"
        username = configuration["username"].string ?? ""
        sender = configuration["sender"].string ?? ""
        adminEmail = mail["admin_email"].string ?? ""
        preset = host == "smtp.qq.com" && security == "ssl" && port == "465" ? "qq465" : host == "smtp.qq.com" && security == "starttls" && port == "587" ? "qq587" : "custom"
    }
    private func save() {
        do {
            let draft = SMTPDraft(host: host, port: port, security: security, username: username, sender: sender, adminEmail: adminEmail)
            let parameters = try draft.parameters(secret: secret)
            secret = ""; attempted = true
            Task { await store.perform("mail.configure", parameters) }
        } catch { store.error = error.localizedDescription }
    }
}
