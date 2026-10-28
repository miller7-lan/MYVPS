import SwiftUI
import DazzleModels

struct DashboardPage: View {
    @Bindable var store: AppStore
    var onUsers: () -> Void = {}
    var onUser: (String) -> Void = { _ in }
    var onSettings: () -> Void = {}
    var body: some View {
        if let snapshot = store.snapshot {
            let data = TrafficOverview(snapshot: snapshot)
            HStack(alignment: .top, spacing: 16) {
                traffic(data)
                VStack(spacing: 14) { cycle; provider(data) }.frame(width: 260)
            }
            users(data)
            if snapshot["totals"]["overallocated"].bool == true {
                Label("已分配额度超过核实的套餐安全池", systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
            }
            history(snapshot)
        } else {
            Card { EmptyState(icon: "chart.pie", title: "正在载入概览", detail: "") }
        }
    }
    private func traffic(_ data: TrafficOverview) -> some View {
        Card {
            HStack {
                Text("流量概览").font(.system(size: 14, weight: .semibold))
                Spacer(); Text("代理载荷").font(.caption2).foregroundStyle(.secondary).help("上传与下载合计；与商家计费流量分别记录。")
            }
            HStack(spacing: 30) {
                PayloadRing(upload: data.upload, download: data.download).padding(.vertical, 7)
                VStack(alignment: .leading, spacing: 19) {
                    trafficLegend("上传", amount: data.upload, color: VPSTheme.accent, icon: "arrow.up.right")
                    trafficLegend("下载", amount: data.download, color: VPSTheme.blue, icon: "arrow.down.left")
                    Divider()
                    HStack(spacing: 5) { Text("已分配共享额度"); Text(Display.bytes(data.allocated)).fontWeight(.medium) }.font(.system(size: 11)).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
    private func trafficLegend(_ title: String, amount: Int64, color: Color, icon: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 14, weight: .medium)).foregroundStyle(color).frame(width: 29, height: 29).background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 3) { Text(title).font(.caption).foregroundStyle(.secondary); Text(Display.bytes(amount)).font(.system(size: 20, weight: .semibold, design: .rounded)) }
        }
    }
    private var cycle: some View {
        let value = store.value("quota_cycle")
        let progress = ChartValues.progress(start: value["start_at"], end: value["end_at"])
        return Card {
            HStack { Label("额度刷新", systemImage: "calendar").font(.caption).foregroundStyle(.secondary); Spacer(); Button(action: onSettings) { Image(systemName: "chevron.right").font(.caption2) }.buttonStyle(.plain).help("设置额度周期") }
            HStack(alignment: .firstTextBaseline) { Text(UIFormat.date(value["end_at"], format: "M月d日")).font(.system(size: 23, weight: .semibold, design: .rounded)); Spacer(); Text(UIFormat.upcoming(value["end_at"])).font(.caption).foregroundStyle(.secondary) }
            VStack(alignment: .leading, spacing: 6) {
                ProgressView(value: progress ?? 0).tint(VPSTheme.accent).accessibilityLabel("管理员设定周期进度")
                HStack { Text(UIFormat.date(value["end_at"], format: "HH:mm")); Spacer(); Text("管理员规则") }.font(.system(size: 10)).foregroundStyle(.secondary)
            }
        }
    }
    private func provider(_ data: TrafficOverview) -> some View {
        Card {
            HStack { Text("服务商余额").font(.caption).foregroundStyle(.secondary); Spacer(); Text("QQG.NET").font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary) }
            if data.providerVerified {
                Text(store.value("provider")["source"].string == "qqg_api"
                     ? store.value("provider")["remaining_display"].text : Display.bytes(data.providerRemaining))
                    .font(.system(size: 23, weight: .semibold, design: .rounded))
                ProgressView(value: Double(data.providerRemaining ?? 0) / Double(data.providerTotal ?? 1)).tint(VPSTheme.accent)
                    .accessibilityLabel("服务商剩余 " + Display.bytes(data.providerRemaining) + "，总量 " + Display.bytes(data.providerTotal))
                Text(store.value("provider")["source"].string == "qqg_api"
                     ? "QQG 标注 GB 按 GiB 计算 · 独立整机计量" : "已核实 · 与代理载荷分开统计")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                if store.value("provider")["source"].string == "qqg_api" {
                    Text("上次同步 " + Display.date(store.value("provider_sync")["last_success_at"]))
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                }
            } else {
                HStack { Text("未同步").font(.system(size: 23, weight: .semibold)); Spacer(); Image(systemName: "cloud.slash").font(.system(size: 21, weight: .light)).foregroundStyle(.tertiary) }
                Button("查看历史记录与接入状态", action: onSettings).font(.system(size: 11)).buttonStyle(.plain).foregroundStyle(VPSTheme.accent)
            }
        }
    }
    private func users(_ data: TrafficOverview) -> some View {
        Card {
            HStack {
                Text("用户用量").font(.system(size: 14, weight: .semibold))
                Text("\(data.users.count)").font(.caption).foregroundStyle(.secondary)
                Spacer(); Button("管理用户", action: onUsers).font(.caption).buttonStyle(.plain).foregroundStyle(VPSTheme.accent)
            }
            if data.users.isEmpty {
                HStack { Text("还没有用户").foregroundStyle(.secondary); Spacer(); Button("添加用户", action: onUsers).buttonStyle(.borderedProminent) }.padding(.vertical, 14)
            } else {
                ForEach(Array(data.users.prefix(4).enumerated()), id: \.element.id) { index, user in
                    Button { onUser(user.id) } label: {
                        HStack(spacing: 12) {
                            IconTile(symbol: user.role == "admin" ? "crown" : "person")
                            VStack(alignment: .leading, spacing: 4) {
                                Text(user.name).font(.system(size: 13, weight: .medium)).lineLimit(1)
                                Text(user.sharesAdministratorBudget ? (store.budget.configured ? "管理员额度池 · 剩余 " + Display.bytes(store.budget.raw["admin_remaining_bytes"].int) : "预算保护尚未启用") : (user.isTrial ? "体验剩余 " : "本期剩余 ") + (user.remaining.map(Display.bytes) ?? "不限额"))
                                    .font(.system(size: 10)).foregroundStyle(.secondary)
                            }.frame(width: 185, alignment: .leading)
                            VStack(alignment: .trailing, spacing: 7) {
                                Text(Display.bytes(user.used)).font(.system(size: 12, weight: .medium, design: .rounded))
                                if !user.sharesAdministratorBudget && user.allowance != nil { UsageTrack(used: user.used, limit: user.allowance) }
                                else { Text("不设个人额度").font(.system(size: 9)).foregroundStyle(.tertiary) }
                            }.frame(maxWidth: .infinity)
                            StatusBadge(user: user).frame(width: 75)
                            Image(systemName: "chevron.right").font(.system(size: 10)).foregroundStyle(.tertiary)
                        }.padding(.vertical, 3).contentShape(Rectangle())
                    }.buttonStyle(.plain).help("查看 \(user.name)")
                    if index < min(data.users.count, 4) - 1 { Divider() }
                }
            }
        }
    }
    @ViewBuilder private func history(_ snapshot: Snapshot) -> some View {
        let cycles = snapshot["cycles"].array.filter { $0["status"].string == "closed" }.prefix(6).reversed()
        if !cycles.isEmpty {
            Card("已结算周期") {
                let maximum = cycles.map { TrafficOverview.sum([$0["report"]["used_upload"].int ?? 0, $0["report"]["used_download"].int ?? 0]) }.max() ?? 0
                HStack(alignment: .bottom, spacing: 16) {
                    ForEach(Array(cycles.enumerated()), id: \.offset) { _, item in
                        let used = TrafficOverview.sum([item["report"]["used_upload"].int ?? 0, item["report"]["used_download"].int ?? 0])
                        VStack(spacing: 7) {
                            Text(Display.bytes(used)).font(.system(size: 10)).foregroundStyle(.secondary)
                            RoundedRectangle(cornerRadius: 5).fill(VPSTheme.accent.opacity(0.55)).frame(height: maximum > 0 ? max(2, 45 * Double(used) / Double(maximum)) : 2)
                            Text(UIFormat.date(item["start_at"], format: "M月")).font(.caption2).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity).accessibilityElement(children: .combine)
                    }
                }.frame(height: 86, alignment: .bottom)
            }
        }
    }
}
