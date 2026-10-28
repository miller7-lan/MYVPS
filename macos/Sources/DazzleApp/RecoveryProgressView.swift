import SwiftUI
import DazzleModels

/// Live progress of the recovery being confirmed. It never locks the window: other users
/// and pages stay usable while read-only checks run about every two seconds.
struct RecoveryProgressBanner: View {
    @Bindable var store: AppStore
    var body: some View {
        if let display = store.recoveryDisplay {
            Card {
                HStack(spacing: 10) {
                    Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(tint(display.progress))
                    Text("恢复连接 · " + display.name).font(.system(size: 13, weight: .semibold))
                    Spacer()
                    if display.progress.finished {
                        Button("关闭") { store.recoveryOutcome = nil }.buttonStyle(.borderless)
                    }
                }
                RecoverySteps(progress: display.progress)
                detail(display.progress, startedAt: display.startedAt)
            }
        }
    }
    @ViewBuilder private func detail(_ progress: RecoveryProgress, startedAt: Date?) -> some View {
        switch progress.outcome {
        case .running:
            if let startedAt {
                TimelineView(.periodic(from: startedAt, by: 1)) { context in
                    Text("已用 \(max(0, Int(context.date.timeIntervalSince(startedAt)))) 秒 · 约每 2 秒自动核对 · 其他用户可照常查看和操作")
                        .font(.caption).foregroundStyle(VPSTheme.muted).monospacedDigit()
                }
            }
        case .succeeded:
            Text("恢复成功 · 计量可信；原订阅、凭据和已用流量保留").font(.caption).foregroundStyle(VPSTheme.accent)
        case .failed(let message):
            Text(message).font(.caption).foregroundStyle(.orange)
        }
    }
    private func tint(_ progress: RecoveryProgress) -> Color {
        if case .failed = progress.outcome { return .orange }
        return VPSTheme.accent
    }
}

/// 停止旧连接 → 重建 → 核对计量 → 恢复成功
struct RecoverySteps: View {
    let progress: RecoveryProgress
    var body: some View {
        HStack(spacing: 6) {
            ForEach(Array(RecoveryProgress.steps.enumerated()), id: \.offset) { index, title in
                if index > 0 { Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.tertiary) }
                Label { Text(title) } icon: { icon(index) }
                    .font(.caption.weight(index == progress.step ? .semibold : .regular))
                    .foregroundStyle(color(index))
            }
        }.accessibilityElement(children: .combine)
            .accessibilityLabel("恢复进度：" + RecoveryProgress.steps[min(progress.step, 3)])
    }
    @ViewBuilder private func icon(_ index: Int) -> some View {
        if case .failed = progress.outcome, index == progress.step {
            Image(systemName: "xmark.circle.fill")
        } else if progress.outcome == .succeeded || index < progress.step {
            Image(systemName: "checkmark.circle.fill")
        } else if index == progress.step {
            ProgressView().controlSize(.mini)
        } else {
            Image(systemName: "circle")
        }
    }
    private func color(_ index: Int) -> Color {
        if case .failed = progress.outcome, index == progress.step { return .orange }
        if progress.outcome == .succeeded || index <= progress.step { return VPSTheme.accent }
        return VPSTheme.muted
    }
}
