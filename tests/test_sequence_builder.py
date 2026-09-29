import unittest
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from src.model.sequence_builder import (
    build_sequences,
    chronological_split,
    densify_pair_windows,
)
from src.model.train import FEATURE_COLS


def make_rows(times, labels=None):
    """Create small synthetic CIC-style window rows for tests."""
    labels = labels or [0] * len(times)
    rows = []

    for index, timestamp in enumerate(times):
        row = {column: float(index) for column in FEATURE_COLS}
        row.update(
            {
                "src_ip": "192.168.10.5",
                "dst_ip": "192.168.10.3",
                "window_start": timestamp,
                "is_attack_window": labels[index],
            }
        )
        rows.append(row)

    return pd.DataFrame(rows)


class SequenceBuilderTests(unittest.TestCase):
    def test_sequence_shape_order_and_future_label_alignment(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        times = [start + timedelta(seconds=30 * i) for i in range(8)]
        labels = [0, 0, 0, 1, 0, 1, 1, 0]
        df = make_rows(times, labels)

        result = build_sequences(
            df,
            sequence_length=3,
            forecast_horizon=2,
            window_seconds=30,
        )

        self.assertEqual(result.X.shape, (4, 3, len(FEATURE_COLS)))
        self.assertEqual(result.y.shape, (4, 2))

        connection_count_index = FEATURE_COLS.index("connection_count")
        np.testing.assert_array_equal(
            result.X[0, :, connection_count_index],
            np.array([0.0, 1.0, 2.0], dtype=np.float32),
        )
        np.testing.assert_array_equal(
            result.y[0],
            np.array([1.0, 0.0], dtype=np.float32),
        )

        self.assertEqual(len(result.metadata), 4)
        self.assertEqual(
            result.metadata.iloc[0]["current_window"],
            times[2],
        )
        self.assertEqual(
            result.metadata.iloc[0]["forecast_window_starts"],
            times[3:5],
        )

    def test_sequences_do_not_cross_missing_time_windows(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        offsets = [0, 30, 60, 120, 150, 180]
        times = [start + timedelta(seconds=value) for value in offsets]
        df = make_rows(times)

        result = build_sequences(
            df,
            sequence_length=2,
            forecast_horizon=1,
            window_seconds=30,
        )

        # One complete 3-window sequence exists on each side of the gap.
        self.assertEqual(result.X.shape, (2, 2, len(FEATURE_COLS)))
        self.assertEqual(result.y.shape, (2, 1))

    def test_densify_fills_short_gap_as_benign_no_flow_window(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        times = [
            start,
            start + timedelta(seconds=60),
        ]
        df = make_rows(times, labels=[0, 1])

        # Another destination has activity for this source at the missing
        # timestamp, so its source-wide features should be copied to the
        # inserted row for the first destination.
        other_destination = df.iloc[0].copy()
        other_destination["dst_ip"] = "192.168.10.9"
        other_destination["window_start"] = start + timedelta(seconds=30)
        other_destination["connection_count"] = 4
        other_destination["unique_destinations"] = 6
        other_destination["lateral_move_flag"] = 1
        other_destination["is_attack_window"] = 1

        df = pd.concat(
            [df, pd.DataFrame([other_destination])],
            ignore_index=True,
        )

        dense = densify_pair_windows(
            df,
            window_seconds=30,
            max_gap_seconds=300,
        )

        target_pair = dense[dense["dst_ip"] == "192.168.10.3"]
        self.assertEqual(len(target_pair), 3)

        inserted = target_pair[
            target_pair["window_start"] == start + timedelta(seconds=30)
        ].iloc[0]

        self.assertEqual(inserted["connection_count"], 0)
        self.assertEqual(inserted["is_attack_window"], 0)
        self.assertEqual(inserted["unique_destinations"], 6)
        self.assertEqual(inserted["lateral_move_flag"], 1)

        sequences = build_sequences(
            dense,
            sequence_length=1,
            forecast_horizon=1,
            window_seconds=30,
        )
        self.assertEqual(sequences.X.shape, (2, 1, len(FEATURE_COLS)))
        np.testing.assert_array_equal(
            sequences.y[:, 0],
            np.array([0.0, 1.0], dtype=np.float32),
        )

    def test_densify_does_not_fill_gaps_over_five_minutes(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        times = [
            start,
            start + timedelta(seconds=360),
        ]
        df = make_rows(times)

        dense = densify_pair_windows(
            df,
            window_seconds=30,
            max_gap_seconds=300,
        )

        self.assertEqual(len(dense), 2)
        self.assertEqual(
            list(dense["window_start"]),
            times,
        )

    def test_chronological_split_has_no_timestamp_overlap(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        times = [start + timedelta(seconds=30 * i) for i in range(20)]
        df = make_rows(times)

        train, validation, test = chronological_split(df)

        self.assertFalse(train.empty)
        self.assertFalse(validation.empty)
        self.assertFalse(test.empty)
        self.assertLess(
            train["window_start"].max(),
            validation["window_start"].min(),
        )
        self.assertLess(
            validation["window_start"].max(),
            test["window_start"].min(),
        )

    def test_rejects_non_finite_feature_values(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        times = [start + timedelta(seconds=30 * i) for i in range(6)]
        df = make_rows(times)
        df.loc[0, FEATURE_COLS[0]] = np.nan

        with self.assertRaisesRegex(ValueError, "NaN or infinite"):
            build_sequences(
                df,
                sequence_length=2,
                forecast_horizon=1,
                window_seconds=30,
            )


if __name__ == "__main__":
    unittest.main()