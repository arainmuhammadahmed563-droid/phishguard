import os, sys, tempfile, unittest
os.environ["PHISH_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features import (extract_features, features_vector, FEATURE_NAMES,
                      registered_domain, brand_mismatch)
from detector import predict, risk_level
from app import app


class Tests(unittest.TestCase):
    def test_features(self):
        f = extract_features("http://192.168.1.1/login@x")
        self.assertEqual(f["has_ip"], 1)
        self.assertEqual(f["has_https"], 0)
        self.assertEqual(extract_features("http://a.com@b.xyz")["has_at"], 1)
        self.assertEqual(len(features_vector("google.com")), len(FEATURE_NAMES))
        self.assertEqual(extract_features("http://x.com/a/b/c.php")["suspicious_ext"], 1)
        self.assertEqual(extract_features("http://x.com/a/b/c")["path_depth"], 3)

    def test_registered_domain_and_brand(self):
        self.assertEqual(registered_domain("mail.google.com"), "google.com")
        self.assertEqual(registered_domain("a.b.co.uk"), "b.co.uk")
        self.assertEqual(brand_mismatch("paypal-secure.xyz"), 1)
        self.assertEqual(brand_mismatch("www.paypal.com"), 0)
        self.assertEqual(brand_mismatch("pineapple.com"), 0)

    def test_bad_input_no_crash(self):
        for u in ["", "   ", "http://", "http://[::1", "://", "a" * 3000]:
            features_vector(u)
            predict(u)

    def test_predictions(self):
        self.assertEqual(predict("https://www.google.com/search?q=python")["label"], "LEGITIMATE")
        self.assertEqual(predict("http://paypal-secure-login.xyz/verify/account.php?id=abc123")["label"], "PHISHING")
        self.assertEqual(predict("http://45.33.12.9/paypal/login/index.php")["label"], "PHISHING")

    def test_trusted_domain_cannot_be_spoofed(self):
        self.assertTrue(predict("https://www.paypal.com/signin")["trusted_domain"])
        self.assertFalse(predict("http://paypal.com.evil-site.xyz/login")["trusted_domain"])
        self.assertFalse(predict("http://paypal.com@evil-site.xyz/login")["trusted_domain"])
        self.assertEqual(predict("http://paypal.com.evil-site.xyz/login")["label"], "PHISHING")

    def test_threshold_and_levels(self):
        url = "http://paypal-secure-login.xyz/verify"
        self.assertEqual(predict(url, 0.99)["label"], "LEGITIMATE")
        self.assertEqual(risk_level(0.1), "LOW")
        self.assertEqual(risk_level(0.5), "MEDIUM")
        self.assertEqual(risk_level(0.9), "HIGH")

    def test_api(self):
        c = app.test_client()
        r = c.post("/api/check", json={"url": "http://secure-apple123.top/login/x.html"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("phishing_probability", r.get_json())
        self.assertIn("risk_level", r.get_json())
        self.assertEqual(c.post("/api/check", json={}).status_code, 400)
        self.assertEqual(c.post("/api/check", json={"url": "a.com", "threshold": 5}).status_code, 400)
        for p in ["/", "/scan", "/bulk", "/history", "/model", "/learn"]:
            self.assertEqual(c.get(p).status_code, 200, p)
        self.assertGreaterEqual(c.get("/api/stats").get_json()["total"], 1)
        self.assertGreaterEqual(len(c.get("/api/history").get_json()), 1)
        self.assertEqual(c.get("/api/health").status_code, 200)
        self.assertEqual(c.get("/api/metrics").status_code, 200)

    def test_batch_api(self):
        c = app.test_client()
        r = c.post("/api/batch", json={"urls": ["https://github.com", "http://45.33.12.9/paypal/login"]})
        j = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual((j["count"], j["phishing"]), (2, 1))
        self.assertEqual(c.post("/api/batch", json={"urls": []}).status_code, 400)
        self.assertEqual(c.post("/api/batch", json={"urls": ["a.com"] * 51}).status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
