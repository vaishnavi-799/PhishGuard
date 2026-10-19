import unittest

from analysis.similarity import jaro, jaro_winkler, levenshtein, levenshtein_similarity, ngram_similarity, ngrams


class SimilarityTests(unittest.TestCase):
    def test_levenshtein_known_values(self):
        for a, b, d in [("kitten", "sitting", 3), ("flaw", "lawn", 2), ("", "abc", 3), ("abc", "", 3), ("same", "same", 0), ("a", "b", 1), ("paypal", "paypa1", 1)]:
            self.assertEqual(levenshtein(a, b), d, (a, b))
            self.assertEqual(levenshtein(b, a), d)  # symmetric

    def test_levenshtein_similarity_bounds(self):
        self.assertEqual(levenshtein_similarity("", ""), 1.0)
        self.assertEqual(levenshtein_similarity("abc", "xyz"), 0.0)
        self.assertAlmostEqual(levenshtein_similarity("paypal", "paypa1"), 5 / 6)

    def test_jaro_and_winkler_reference_values(self):
        # classic textbook examples
        self.assertAlmostEqual(jaro("MARTHA", "MARHTA"), 0.9444, places=4)
        self.assertAlmostEqual(jaro_winkler("MARTHA", "MARHTA"), 0.9611, places=4)
        self.assertAlmostEqual(jaro("DIXON", "DICKSONX"), 0.7667, places=4)
        self.assertAlmostEqual(jaro_winkler("DIXON", "DICKSONX"), 0.8133, places=4)
        self.assertEqual(jaro_winkler("abc", "abc"), 1.0)
        self.assertEqual(jaro_winkler("abc", "xyz"), 0.0)
        self.assertEqual(jaro("", "a"), 0.0)

    def test_winkler_rewards_common_prefix(self):
        self.assertGreater(jaro_winkler("paypal", "paypa1"), jaro("paypal", "paypa1"))

    def test_ngrams(self):
        self.assertEqual(dict(ngrams("abc", 2)), {"ab": 1, "bc": 1})
        self.assertEqual(dict(ngrams("a", 2)), {"a": 1})
        self.assertAlmostEqual(ngram_similarity("night", "nacht"), 0.25)  # shares only "ht"
        self.assertEqual(ngram_similarity("abc", "abc"), 1.0)
        self.assertEqual(ngram_similarity("", ""), 1.0)
        self.assertEqual(ngram_similarity("ab", "cd"), 0.0)
        self.assertAlmostEqual(ngram_similarity("paypal", "paypa1"), ngram_similarity("paypa1", "paypal"))


if __name__ == "__main__":
    unittest.main()
