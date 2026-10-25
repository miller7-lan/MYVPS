import SwiftUI
import DazzleModels

struct ManagementStatusCard: View {
    @Bindable var store: AppStore
    private var confirmedRunning: Int {
        store.users.filter { $0.raw["runtime_state"].string == "running" && $0.raw["runtime_verified_at"].string != nil }.count
    }
    var body: some View {
        Card {
            HStack(spacing: 12) {
                Image(systemName: "square.stack.3d.up").font(.title2).foregroundStyle(VPSTheme.accent)
                VStack(alignment: .leading, spacing: 5) {
                    Text("新旧入口并存").font(.system(size: 13, weight: .semibold))
                    Text("旧 443 代理与 8443 订阅保留，新程序不管理或撤销它们。")
                        .font(.caption).foregroundStyle(VPSTheme.muted)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 5) {
                    Text("新程序 \(confirmedRunning) / \(store.users.count) 运行").font(.caption)
                    Text(store.serverReachable ? "控制器已连接" : "显示上次快照").font(.caption2).foregroundStyle(store.serverReachable ? VPSTheme.accent : .orange)
                }
            }
            if store.serverNeedsReview {
                HStack {
                    Label("上次修改结果待核对，没有自动重试", systemImage: "exclamationmark.circle").font(.caption).foregroundStyle(.orange)
                    Spacer(); Button("核对状态") { Task { await store.refresh() } }.disabled(store.busy)
                }
            } else if let problem = store.serverRefreshError {
                Label(problem, systemImage: "wifi.exclamationmark").font(.caption).foregroundStyle(.orange)
            }
            DisclosureGroup("管理范围") {
                VStack(spacing: 8) {
                    ValueRow(name: "服务器身份", value: store.serverContext?.serverID ?? "未连接")
                    ValueRow(name: "可用能力", value: "仅根策略登记的新用户与实例")
                    ValueRow(name: "状态刷新", value: "前台约 8 秒，不轮询商家 API")
                    ValueRow(name: "旧服务 / SSH / 防火墙", value: "没有修改入口")
                }.padding(.top, 8)
            }.font(.caption).foregroundStyle(VPSTheme.muted)
        }
    }
}
