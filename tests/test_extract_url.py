import unittest

from prompt_guardian.helpers import extract_urls


class TestExtractUrls(unittest.TestCase):

    def test_extract_simple_url(self):
        text = "Check out this website: https://www.example.com for more information."
        expected = ["https://www.example.com"]
        self.assertEqual(extract_urls(text), expected)

    def test_extract_multiple_urls(self):
        text = "Visit https://www.example.com and http://www.test.com."
        expected = ["https://www.example.com", "http://www.test.com"]
        self.assertEqual(expected, extract_urls(text))

    def test_extract_url_with_ipv4(self):
        text = "Access the router interface at http://201.168.0.1 for settings."
        expected = ["http://201.168.0.1", "201.168.0.1"]
        self.assertEqual(expected, extract_urls(text))

    # def test_extract_url_with_ipv6(self):
    #     text = "Our server is located at https://[2001:db8::1]:8080/configuration."
    #     expected = ["https://[2001:db8::1]:8080/configuration"]
    #     self.assertEqual(expected, extract_urls(text))

    def test_no_url(self):
        text = "There is no URL in this text."
        expected = []
        self.assertEqual(extract_urls(text), expected)

    def test_url_in_complex_sentence(self):
        text = "For more info, visit https://example.com/page or contact us at info@example.com."
        expected = ['https://example.com/page', 'atinfo@example.com']
        self.assertEqual(expected, extract_urls(text),)

    def test_mixed_private_type_urls_in_text(self):
        text = "Check these: https://www.example.com, http://192.168.1.1, and https://[2001:db8::1]."
        expected = ['https://www.example.com',
                    'http://192.168.1.1',
                    'https://2001:db8::1',
                    '192.168.1.1',
                    '2001:db8::1']
        self.assertEqual(expected, extract_urls(text))

    def test_mixed_type_urls_in_text(self):
        text = "Check these: https://www.example.com, http://203.0.113.1, and https://www.ipv6-example.com."
        expected = ['https://www.example.com',
                    'http://203.0.113.1',
                    'https://www.ipv6-example.com',
                    '203.0.113.1']
        self.assertEqual(expected, extract_urls(text))

    def test_text_with_almost_urls(self):
        text = "This is not a URL: www.example without http, nor is example.com without the scheme."
        expected = []
        self.assertEqual(extract_urls(text), expected)

    def test_text_with_incomplete_url(self):
        text = "Sometimes people write http:// without following it with a domain."
        expected = ['http://without']
        self.assertEqual(expected, extract_urls(text))

    def test_text_with_broken_url(self):
        text = "Check this broken URL: http://www.exa mple.com with a space."
        expected = ["http://www.exa"]
        self.assertEqual(expected, extract_urls(text))


if __name__ == '__main__':
    unittest.main()
