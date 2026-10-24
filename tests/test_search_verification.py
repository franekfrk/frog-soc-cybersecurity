import json
import unittest
import test_features


class SearchVerificationTests(unittest.TestCase):
    def setUp(self):
        test_features.FeatureTests.setUp(self)
        self.path = self.root / 'site-verification.json'

    def test_tokens_in_head_and_no_arbitrary_html(self):
        self.path.write_text(json.dumps({'google-site-verification': 'Google_123-abc',
                                         'msvalidate.01': 'BING123',
                                         'evil': '<script>bad</script>'}))
        page = self.app.trap_hub('example.com')
        head = page.split('</head>')[0]
        self.assertIn('<meta name="google-site-verification" content="Google_123-abc">', head)
        self.assertIn('<meta name="msvalidate.01" content="BING123">', head)
        self.assertNotIn('<script>bad', page)
        self.path.write_text(json.dumps({'google-site-verification': '\"><script>bad</script>', 'msvalidate.01': ['bad']}))
        self.assertEqual(self.app.site_verification_meta(), '')

    def test_missing_malformed_and_oversized(self):
        self.assertEqual(self.app.site_verification_meta(), '')
        for data in ('{', '[]', '{"msvalidate.01":"'+'a'*5000+'"}'):
            self.path.write_text(data)
            self.assertEqual(self.app.site_verification_meta(), '')
