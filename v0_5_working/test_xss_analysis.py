
import unittest

from probe import MARKER, analyze_reflection


class TestXSSAnalysis(unittest.TestCase):

    def test_raw_html_element(self):
        body = f"<html><body><p>{MARKER}</p></body></html>"
        result = analyze_reflection(body)

        self.assertEqual(
            result["classification"],
            "potential_html_injection",
        )
        self.assertTrue(result["parsed_as_html_tag"])

    def test_escaped_reflection(self):
        body = (
            "<html><body><p>"
            "&lt;FPTK_XSS_A91&gt;"
            "</p></body></html>"
        )
        result = analyze_reflection(body)

        self.assertEqual(
            result["classification"],
            "escaped_reflection",
        )
        self.assertFalse(result["parsed_as_html_tag"])

    def test_raw_reflection_in_attribute(self):
        body = (
            '<html><body><div data-test="'
            + MARKER
            + '"></div></body></html>'
        )
        result = analyze_reflection(body)

        self.assertEqual(
            result["classification"],
            "raw_reflection_in_attribute",
        )
        self.assertTrue(result["attribute_contexts"])

    def test_no_reflection(self):
        body = "<html><body><p>Hello world</p></body></html>"
        result = analyze_reflection(body)

        self.assertEqual(
            result["classification"],
            "not_reflected",
        )

    def test_classification_does_not_confirm_xss(self):
        body = f"<html><body>{MARKER}</body></html>"
        result = analyze_reflection(body)

        self.assertFalse(result["confirmed_vulnerability"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
