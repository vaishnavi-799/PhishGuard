import unittest

from analysis.homograph import analyze_homograph, decode_punycode_label, script_of, skeleton, to_ascii_host, to_unicode_host


class HomographTests(unittest.TestCase):
    def test_plain_ascii_host_is_not_idn(self):
        r = analyze_homograph("www.example.com")
        self.assertFalse(r["is_idn"] or r["is_suspicious"] or r["mixed_script_labels"])

    def test_punycode_decoding_roundtrip(self):
        self.assertEqual(decode_punycode_label("xn--80ak6aa92e"), "аррӏе")
        self.assertEqual(to_unicode_host("xn--80ak6aa92e.com"), "аррӏе.com")
        self.assertEqual(to_ascii_host("аррӏе.com"), "xn--80ak6aa92e.com")
        self.assertEqual(decode_punycode_label("xn--%%%"), "xn--%%%")  # undecodable stays as-is

    def test_cyrillic_lookalike_of_a_brand(self):
        r = analyze_homograph("раураl.com")  # Cyrillic р,а,у,р,а + Latin l
        self.assertTrue(r["is_idn"] and r["contains_non_ascii"])
        self.assertEqual(r["brand_matches"][0]["brand"], "PayPal")
        self.assertEqual(r["skeleton"], "paypal")
        self.assertTrue(r["is_suspicious"])
        self.assertEqual(r["mixed_script_labels"], ["раураl"])

    def test_punycode_form_is_detected_too(self):
        r = analyze_homograph("xn--80ak6aa92e.com")
        self.assertEqual(r["punycode_labels"], ["xn--80ak6aa92e"])
        self.assertEqual(r["brand_matches"][0]["brand"], "Apple")
        self.assertTrue(r["whole_script_confusable"])

    def test_greek_and_armenian_confusables(self):
        self.assertEqual(skeleton("ρaypal"), "paypal")
        self.assertEqual(skeleton("ɡoogle"), "google")

    def test_hidden_and_bidi_characters(self):
        r = analyze_homograph("pay\u200bpal.com")
        self.assertEqual(r["hidden_characters"], ["U+200B"])
        self.assertTrue(r["is_suspicious"])
        self.assertEqual(r["brand_matches"][0]["brand"], "PayPal")

    def test_legitimate_idn_is_not_flagged_as_brand_attack(self):
        r = analyze_homograph("münchen.de")
        self.assertTrue(r["is_idn"])
        self.assertEqual(r["brand_matches"], [])
        self.assertFalse(r["is_suspicious"])
        r = analyze_homograph("日本語.jp")
        self.assertFalse(r["is_suspicious"])

    def test_script_detection(self):
        self.assertEqual(script_of("a"), "LATIN")
        self.assertEqual(script_of("а"), "CYRILLIC")
        self.assertEqual(script_of("α"), "GREEK")
        self.assertEqual(script_of("-"), "COMMON")
        self.assertEqual(script_of("5"), "COMMON")

    def test_genuine_brand_domain_is_not_a_match(self):
        self.assertEqual(analyze_homograph("paypal.com")["brand_matches"], [])


if __name__ == "__main__":
    unittest.main()
