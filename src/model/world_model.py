"""GRU World Model for direct multi-step future attack forecasting."""

from typing import Optional, Union

import numpy as np
import torch
from torch import nn


class GRUWorldModel(nn.Module):
    """Predict future attack labels from a sequence of network windows.

    Input shape:
        (batch_size, sequence_length, feature_count)

    Training output:
        Raw logits of shape (batch_size, forecast_horizon), intended for
        torch.nn.BCEWithLogitsLoss.

    Inference:
        forecast() returns one probability for each requested future step.
        Each horizon has its own learned output; probabilities are not copied
        from one step to another.
    """

    def __init__(
        self,
        feature_count: int = 16,
        sequence_length: int = 5,
        forecast_horizon: int = 3,
        hidden_size: int = 32,
        num_layers: int = 1,
        dropout: float = 0.1,
    ) -> None:
        super().__init__()

        if feature_count <= 0:
            raise ValueError("feature_count must be greater than zero")
        if sequence_length <= 0:
            raise ValueError("sequence_length must be greater than zero")
        if forecast_horizon <= 0:
            raise ValueError("forecast_horizon must be greater than zero")
        if hidden_size <= 0:
            raise ValueError("hidden_size must be greater than zero")
        if num_layers <= 0:
            raise ValueError("num_layers must be greater than zero")
        if not 0.0 <= dropout < 1.0:
            raise ValueError("dropout must be in the range [0.0, 1.0)")

        self.feature_count = feature_count
        self.sequence_length = sequence_length
        self.forecast_horizon = forecast_horizon
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.dropout_probability = dropout

        # PyTorch's GRU dropout only applies between recurrent layers.
        gru_dropout = dropout if num_layers > 1 else 0.0
        self.gru = nn.GRU(
            input_size=feature_count,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=gru_dropout,
        )
        self.output_dropout = nn.Dropout(dropout)
        self.output_layer = nn.Linear(hidden_size, forecast_horizon)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Return raw future-step logits for use by the training loss."""
        if not isinstance(x, torch.Tensor):
            raise TypeError("x must be a torch.Tensor")
        if x.ndim != 3:
            raise ValueError(
                "Expected input shape (batch, sequence_length, feature_count); "
                f"received {tuple(x.shape)}"
            )
        if x.shape[1] != self.sequence_length:
            raise ValueError(
                f"Expected sequence_length={self.sequence_length}, "
                f"received {x.shape[1]}"
            )
        if x.shape[2] != self.feature_count:
            raise ValueError(
                f"Expected feature_count={self.feature_count}, "
                f"received {x.shape[2]}"
            )
        if not x.is_floating_point():
            raise TypeError("x must contain floating-point values")
        if not torch.isfinite(x).all():
            raise ValueError("x contains NaN or infinite values")

        _, hidden = self.gru(x)
        last_layer_hidden = hidden[-1]
        logits = self.output_layer(self.output_dropout(last_layer_hidden))
        return logits

    def forecast(
        self,
        sequence: Union[np.ndarray, torch.Tensor],
        horizon: Optional[int] = None,
    ) -> np.ndarray:
        """Return future attack probabilities for one sequence or a batch.

        A single sequence has shape (sequence_length, feature_count).
        A batch has shape (batch_size, sequence_length, feature_count).

        The returned array has shape (horizon,) for one sequence or
        (batch_size, horizon) for a batch.
        """
        requested_horizon = (
            self.forecast_horizon if horizon is None else horizon
        )
        if not isinstance(requested_horizon, int):
            raise TypeError("horizon must be an integer")
        if not 1 <= requested_horizon <= self.forecast_horizon:
            raise ValueError(
                f"horizon must be between 1 and the trained model horizon "
                f"({self.forecast_horizon})"
            )

        if isinstance(sequence, np.ndarray):
            x = torch.as_tensor(sequence, dtype=torch.float32)
        elif isinstance(sequence, torch.Tensor):
            x = sequence.to(dtype=torch.float32)
        else:
            raise TypeError("sequence must be a NumPy array or torch.Tensor")

        single_sequence = x.ndim == 2
        if single_sequence:
            x = x.unsqueeze(0)

        was_training = self.training
        self.eval()
        try:
            with torch.no_grad():
                probabilities = torch.sigmoid(self.forward(x))
                probabilities = probabilities[:, :requested_horizon]
        finally:
            self.train(was_training)

        result = probabilities.cpu().numpy()
        return result[0] if single_sequence else result