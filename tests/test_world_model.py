import pytest
pytest.importorskip("torch")
import unittest

import numpy as np
import torch

from src.model.train import FEATURE_COLS
from src.model.world_model import GRUWorldModel


class GRUWorldModelTests(unittest.TestCase):
    def setUp(self):
        torch.manual_seed(7)
        self.model = GRUWorldModel(
            feature_count=len(FEATURE_COLS),
            sequence_length=5,
            forecast_horizon=3,
            hidden_size=16,
        )
        self.sequence = np.zeros(
            (5, len(FEATURE_COLS)),
            dtype=np.float32,
        )

    def test_forward_returns_one_logit_per_forecast_step(self):
        batch = torch.zeros(
            (4, 5, len(FEATURE_COLS)),
            dtype=torch.float32,
        )

        logits = self.model(batch)

        self.assertEqual(tuple(logits.shape), (4, 3))

    def test_forecast_returns_valid_probabilities_for_requested_horizon(self):
        probabilities = self.model.forecast(self.sequence, horizon=3)

        self.assertEqual(probabilities.shape, (3,))
        self.assertTrue(np.isfinite(probabilities).all())
        self.assertTrue(np.all(probabilities >= 0.0))
        self.assertTrue(np.all(probabilities <= 1.0))

    def test_forecast_supports_one_step_horizon(self):
        probabilities = self.model.forecast(self.sequence, horizon=1)

        self.assertEqual(probabilities.shape, (1,))
        self.assertTrue(0.0 <= float(probabilities[0]) <= 1.0)

    def test_batched_forecast_returns_one_row_per_sequence(self):
        batch = np.zeros(
            (2, 5, len(FEATURE_COLS)),
            dtype=np.float32,
        )

        probabilities = self.model.forecast(batch, horizon=3)

        self.assertEqual(probabilities.shape, (2, 3))
        self.assertTrue(np.isfinite(probabilities).all())

    def test_repeated_inference_is_deterministic_in_eval_mode(self):
        first = self.model.forecast(self.sequence, horizon=3)
        second = self.model.forecast(self.sequence, horizon=3)

        np.testing.assert_allclose(first, second)

    def test_rejects_wrong_sequence_length(self):
        wrong_length = np.zeros(
            (4, len(FEATURE_COLS)),
            dtype=np.float32,
        )

        with self.assertRaisesRegex(ValueError, "sequence_length"):
            self.model.forecast(wrong_length)

    def test_rejects_wrong_feature_count(self):
        wrong_features = np.zeros((5, len(FEATURE_COLS) - 1), dtype=np.float32)

        with self.assertRaisesRegex(ValueError, "feature_count"):
            self.model.forecast(wrong_features)

    def test_rejects_non_finite_input(self):
        invalid = self.sequence.copy()
        invalid[0, 0] = np.nan

        with self.assertRaisesRegex(ValueError, "NaN or infinite"):
            self.model.forecast(invalid)

    def test_rejects_horizon_larger_than_trained_output(self):
        with self.assertRaisesRegex(ValueError, "trained model horizon"):
            self.model.forecast(self.sequence, horizon=5)


if __name__ == "__main__":
    unittest.main()