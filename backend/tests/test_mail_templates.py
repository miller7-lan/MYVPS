"""Copy contract tests, independent of SMTP and production settings."""
import unittest

from dazzle.mail_templates import BRAND, moment, render


class MailTemplateTests(unittest.TestCase):
    def test_each_event_has_a_chinese_subject_without_raw_kind(self):
        kinds = ("verification", "portal_verification", "portal_welcome", "portal_application_notice",
                 "portal_approved", "portal_rejected", "portal_activated", "subscription_resend", "quota_threshold", "quota_exceeded",
                 "cycle_started", "quota_reset", "cycle_summary", "quota_cycle_upcoming", "provider_cycle_upcoming",
                 "provider_reset_waiting", "provider_reset_confirmed", "provider_observation", "metering_failure",
                 "runtime_pause_failed", "pool_protection", "recovery_success", "user_deleted", "test",
                 "trial_started", "trial_expiring", "trial_expired", "trial_exhausted")
        for kind in kinds:
            with self.subTest(kind=kind):
                value = render(kind)
                self.assertTrue(value.subject.startswith(BRAND))
                self.assertNotIn(kind, value.subject)
                self.assertTrue(any("\u4e00" <= character <= "\u9fff" for character in value.subject))
                self.assertTrue(value.body)

    def test_private_code_and_links_never_enter_public_queue_copy(self):
        code = "382941"
        verify = render("portal_verification", code=code)
        self.assertIn(code, verify.body)
        self.assertNotIn(code, verify.public_body)
        links = {"clash": "https://example.test/private/config.yaml", "shadowrocket": "https://example.test/private/nodes.txt"}
        for kind in ("portal_activated", "subscription_resend"):
            activated = render(kind, links=links)
            for link in links.values():
                self.assertIn(link, activated.body)
                self.assertNotIn(link, activated.public_body)

    def test_account_mail_uses_plain_language_and_keeps_import_guidance(self):
        kinds = ("portal_verification", "portal_welcome", "portal_approved", "portal_rejected",
                 "portal_activated", "subscription_resend", "recovery_success", "user_deleted", "test")
        for kind in kinds:
            value = render(kind)
            for term in ("代理", "凭据", "节点"):
                self.assertNotIn(term, value.subject + value.body)
        for kind in ("portal_activated", "subscription_resend"):
            value = render(kind)
            for label in ("Clash / mihomo", "Shadowrocket", "对应的地址", "勿公开或转发", "使用你的额度"):
                self.assertIn(label, value.body)

    def test_pause_and_reset_copy_preserve_observation_limits(self):
        self.assertIn("已请求暂停", render("quota_exceeded").body)
        self.assertIn("尚未确认", render("runtime_pause_failed").subject)
        self.assertIn("不代表服务商流量已重置", render("cycle_started").body)
        self.assertIn("不会因此提前发放额度", render("provider_cycle_upcoming").body)
        self.assertIn("不代表暂停已经成功", render("runtime_pause_failed").body)

    def test_usage_and_expiry_are_human_readable_with_explicit_timezone(self):
        value = render("trial_started", allowance_bytes=5_000_000_000, expires_at="2026-10-26T08:19:00Z")
        self.assertIn("5.00 GB", value.body)
        self.assertIn("2026年10月26日 16:19", value.body)
        self.assertIn("北京时间", value.body)
        self.assertEqual(moment("invalid"), "未确认")
        self.assertEqual(moment("2026-10-26T08:19:00"), "未确认")

    def test_unknown_kind_has_a_safe_chinese_fallback(self):
        self.assertNotIn("internal_event_key", render("internal_event_key").subject)
