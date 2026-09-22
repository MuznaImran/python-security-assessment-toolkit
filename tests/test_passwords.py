import string
import unittest

from cybersec_toolkit.passwords import (
    AMBIGUOUS_CHARACTERS,
    analyze_password,
    estimate_pool_entropy,
    generate_password,
)


class PasswordTests(unittest.TestCase):
    def test_generated_password_has_every_enabled_group(self):
        for _ in range(20):
            password = generate_password(24)
            self.assertEqual(len(password), 24)
            self.assertTrue(any(ch in string.ascii_lowercase for ch in password))
            self.assertTrue(any(ch in string.ascii_uppercase for ch in password))
            self.assertTrue(any(ch in string.digits for ch in password))
            self.assertTrue(any(ch in string.punctuation for ch in password))

    def test_excludes_ambiguous_characters(self):
        password = generate_password(128, exclude_ambiguous=True)
        self.assertFalse(set(password) & AMBIGUOUS_CHARACTERS)

    def test_single_group_and_invalid_options(self):
        password = generate_password(
            14, use_lowercase=False, use_uppercase=False, use_symbols=False
        )
        self.assertEqual(len(password), 14)
        self.assertTrue(password.isdigit())
        with self.assertRaisesRegex(ValueError, "cover every"):
            generate_password(3)
        with self.assertRaisesRegex(ValueError, "enable"):
            generate_password(
                10,
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_symbols=False,
            )
        with self.assertRaises(TypeError):
            generate_password(True)

    def test_strength_feedback_discloses_limitations(self):
        weak = analyze_password("password123")
        self.assertEqual(weak["score"], 0)
        self.assertIn("breach exposure", weak["limitations"])
        stronger = analyze_password("m9&Qx2!Vz7#Rt4@p")
        self.assertGreater(stronger["score"], weak["score"])
        self.assertEqual(stronger["rating"], "very strong")
        self.assertNotIn("m9&Qx2!Vz7#Rt4@p", repr(stronger))

    def test_repeated_and_sequential_passwords_penalized(self):
        self.assertLessEqual(analyze_password("aaaaaaaaaaaaaaaa")["score"], 1)
        self.assertLessEqual(analyze_password("Abcd1234!Qx2")["score"], 2)
        self.assertEqual(analyze_password("")["rating"], "very weak")
        with self.assertRaises(TypeError):
            analyze_password(None)

    def test_entropy_is_a_pool_size_approximation(self):
        lower_only = estimate_pool_entropy(
            8,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False,
        )
        self.assertEqual(lower_only, 37.6)
        self.assertGreater(estimate_pool_entropy(20), estimate_pool_entropy(12))


if __name__ == "__main__":
    unittest.main()
