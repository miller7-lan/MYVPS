"""Chinese notification copy; delivery authorization and retries stay in mail.py.

Only callers handling a private mail payload may pass codes or subscription
links. ``public_body`` is safe to persist in ordinary queue summaries; ``body``
may contain the explicitly supplied private values.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

BRAND = "Dazzle’VPS"


@dataclass(frozen=True)
class MailTemplate:
    subject: str
    body: str
    public_body: str


def size(value):
    if type(value) is not int or value < 0:
        return "未确认"
    return f"{value / 1_000_000_000:.2f} GB" if value >= 1_000_000_000 else f"{value / 1_000_000:.1f} MB"


def moment(value):
    if not value:
        return "未确认"
    try:
        current = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if current.tzinfo is None:
            return "未确认"
        return current.astimezone(ZoneInfo("Asia/Shanghai")).strftime("%Y年%m月%d日 %H:%M") + "（北京时间）"
    except (ValueError, TypeError):
        return "未确认"


def render(kind: str, **context) -> MailTemplate:
    """Render one event without changing its identity or claiming delivery.

    Context is optional: name, used_bytes, allowance_bytes, threshold_percent,
    expires_at, cycle_start, cycle_end, detail, reason, code, links. Unknown
    events receive a Chinese fallback title and never expose their raw kind.
    """
    name = str(context.get("name") or "").strip()[:80]
    greeting = f"{name}，你好：" if name else "你好："
    usage = f"当前已用 {size(context.get('used_bytes'))}，本期额度 {size(context.get('allowance_bytes'))}。"
    title, text = "服务通知", "服务状态有更新，请登录个人中心或联系管理员查看。"
    private = None
    if kind in {"verification", "portal_verification"}:
        title = "邮箱验证码"
        text = "邮箱验证码已生成，仅用于本次邮箱验证或登录。"
        code = str(context.get("code") or "")
        private = f"你的邮箱验证码是：{code}\n\n验证码10分钟内有效，最多可尝试5次。请勿向他人透露。若非本人操作，请忽略此邮件。"
        if kind == "portal_verification":
            private += "\n\n已有账户可直接登录个人中心；首次申请需等待管理员审核。"
    elif kind == "portal_welcome":
        title = "邮箱绑定成功，等待审核"
        text = "你的邮箱已绑定，申请正在等待管理员审核。连接开通后，你会收到个人订阅邮件，也可以登录个人中心查看进度。"
    elif kind == "portal_application_notice":
        title = "有一份新的注册申请"
        text = "一位用户已完成邮箱验证，正在等待审核。请在 Mac 管理 App 的“注册申请”中查看并决定是否启用。"
    elif kind == "portal_approved":
        title = "申请已通过，正在开通"
        text = "你的申请已通过，连接正在准备中。个人中心显示“已启用”后即可使用，届时会另发个人订阅邮件。"
    elif kind == "portal_rejected":
        title = "申请审核结果"
        text = "这次申请暂未通过。如需了解原因或重新申请，请联系管理员。"
        if context.get("reason"):
            text += "\n\n管理员说明：" + str(context["reason"])[:200]
    elif kind in {"portal_activated", "subscription_resend"}:
        title = "连接已开通，个人订阅已就绪" if kind == "portal_activated" else "你的个人订阅资料"
        by_user = kind == "subscription_resend" and context.get("requested_by") == "user"
        text = ("连接已开通，用量统计正常；个人订阅通知已生成。" if kind == "portal_activated" else
                "你在个人中心请求重新发送了个人订阅邮件，请查看已验证邮箱。" if by_user else
                "管理员已重新生成个人订阅邮件，请查看已验证邮箱。")
        links = context.get("links") or {}
        introduction = ("你的连接已开通，现可导入或更新个人订阅。" if kind == "portal_activated" else
                        "这是你在个人中心请求重新发送的使用资料。原订阅继续有效，可在对应客户端导入或更新。"
                        "如非本人操作，请尽快联系管理员。" if by_user else
                        "这是管理员为你重新发送的使用资料。原订阅继续有效，可在对应客户端导入或更新。")
        private = (introduction + "\n\n"
                   "Clash / mihomo（适用于 Clash Verge Rev 等客户端）：\n" + str(links.get("clash") or "未提供") +
                   "\n\nShadowrocket：\n" + str(links.get("shadowrocket") or "未提供") +
                   "\n\n请选择与你使用的客户端对应的地址，按客户端提示导入或更新即可。"
                   "\n\n请妥善保管个人链接，勿公开或转发；他人持有链接后也可能使用你的额度。")
    elif kind in {"quota_threshold", "quota_warning"}:
        title = "流量额度即将用尽"
        text = usage + "\n\n用量已达到提醒阈值。达到额度上限后，连接将按规则暂停；如需增加额度，请联系管理员。"
    elif kind == "quota_exceeded":
        title = "本期流量额度已用尽"
        text = usage + "\n\n系统已请求暂停此账户；是否已断开，以服务实际状态为准。你可以联系管理员调整额度，或等待符合规则的新周期恢复。"
    elif kind in {"cycle_started", "quota_reset"}:
        title = "新的额度周期已生效"
        text = "管理员设定的新额度周期已生效。基础额度继续保留，上期临时追加额度已结束。手动暂停、用量异常和已撤销账户不会因此恢复。"
        if context.get("cycle_end"):
            text += "\n\n本期预计结束：" + moment(context["cycle_end"]) + "。"
        text += "\n\n这是用户额度周期通知，不代表服务商流量已重置。"
    elif kind == "cycle_summary":
        title = "上期流量使用汇总"
        text = "上一额度周期已归档，用量记录和报告已保存。请在 Mac 管理 App 查看各账户用量与统计状态。连接用量与服务商计费可能存在差异。"
    elif kind == "quota_cycle_upcoming":
        title = "额度周期将在24小时内结束"
        text = "管理员设定的额度周期将在24小时内结束。请提前核对额度安排与临时追加额度，服务器会按计划处理，无需保持 Mac 开机。这不代表服务商流量即将重置。"
    elif kind == "provider_cycle_upcoming":
        title = "服务商预计重置时间临近"
        text = "已核实的服务商预计重置时间将在24小时内到达。预计时间不是重置成功确认；系统仍将等待实际数据，不会因此提前发放额度。"
    elif kind == "provider_reset_waiting":
        title = "正在等待服务商重置确认"
        text = "服务商预计重置时间已到，目前仍未取得实际重置证据。账本及原有限制继续保留；请核对服务商面板或官方数据。"
    elif kind in {"provider_reset_confirmed", "provider_observation", "provider_changed", "provider_warning", "provider_observed"}:
        title = "服务商流量信息已更新"
        text = "已记录新的服务商流量资料，请在 Mac 管理 App 核对来源与可信状态。服务商记录与管理员额度周期分别保存，本次记录不会重复发放用户额度。"
    elif kind == "provider_auto_reset":
        title = "QQG 流量已重置"
        text = "自动同步发现 QQG 已用流量归零或大幅下降，已记录为服务商实际重置。管理员设定的用户额度周期仍按原计划切换，不会因此提前发放或重置用户额度。"
    elif kind == "provider_auto_low":
        title = "QQG 剩余流量偏低"
        text = "QQG 实时剩余流量已低于提醒线。管理员共享额度会按 QQG 实际剩余自动收紧，已分配给注册用户的额度不变。请在 Mac 管理 App 核对用量，必要时调整预算或在 QQG 购买流量包。"
    elif kind == "provider_sync_failed":
        title = "QQG 自动同步中断"
        text = "已有一段时间无法读取 QQG 流量数据。代理连接不受影响；6 小时内仍按上次读数扣除本地用量估算，之后只按本地预算计算。请检查 API 密钥、IP 白名单或 QQG 网站状态。"
    elif kind == "metering_failure":
        title = "用量统计异常，需要检查"
        text = "系统暂时无法确认连续的用量统计，已记录异常，并按账户规则限制相关连接。请在 Mac 管理 App 查看实际状态；恢复前请核对中断期间的用量，保留已有记录。"
    elif kind == "runtime_pause_failed":
        title = "账户暂停尚未确认，请优先处理"
        text = "系统尚未确认此账户的连接已经停止，原连接可能仍在使用。请尽快查看实际状态；此次通知不代表暂停已经成功。"
    elif kind == "recovery_success":
        title = "账户连接已恢复"
        text = "你的连接已恢复，用量统计正常。原订阅继续有效，已用流量和历史记录均保留；如客户端仍显示异常，请更新订阅后重试。"
    elif kind == "pool_protection":
        title = "总流量保护已触发"
        text = "可用流量已触及设定的安全边界，系统已请求限制相关账户。请核对实际剩余流量、分配预算和暂停结果，避免影响其他用户已分配的额度。"
    elif kind in {"user_revoked", "credentials_revoked", "user_deleted"}:
        title = "账户访问已撤销"
        text = "此账户的个人链接与访问设置已撤销，旧订阅不能继续更新。服务器正在确认连接停止结果，已使用流量与必要记录继续保留。如有疑问，请联系管理员。"
    elif kind == "trial_started":
        title = "临时体验已开通"
        text = "你的临时体验已开通。体验期总额度为 " + size(context.get("allowance_bytes")) + "，有效至 " + moment(context.get("expires_at")) + "。到期或用尽额度后将停止，期间不会自动续期或刷新体验额度。"
    elif kind == "trial_expiring":
        title = "临时体验即将到期"
        text = "临时体验将于 " + moment(context.get("expires_at")) + " 结束。" + usage + " 到期后原订阅和访问权限将失效，如需继续使用，请联系管理员。"
    elif kind in {"trial_expired", "trial_exhausted"}:
        title = "临时体验已结束"
        text = ("临时体验已到期。" if kind == "trial_expired" else "临时体验额度已用尽。") + "原订阅已失效，系统正在确认连接停止并清理体验设置。已使用流量记录继续保留，如需继续使用，请联系管理员。"
    elif kind == "test":
        title = "邮件通知测试"
        text = "这是一封邮件通知测试。如果你已读到这封邮件，说明本次邮件已到达你的邮箱。此邮件不含个人访问设置或订阅链接。"
    if context.get("detail") and kind not in {"verification", "portal_verification", "portal_activated", "subscription_resend"}:
        text += "\n\n补充信息：" + str(context["detail"])[:2000]
    footer = "\n\n" + BRAND + "\n此邮件由系统发送，请勿直接回复。请妥善保管验证码与个人链接。"
    public = greeting + "\n\n" + text + footer
    return MailTemplate(BRAND + " · " + title, greeting + "\n\n" + (private or text) + footer, public)
