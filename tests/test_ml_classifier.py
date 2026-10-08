from pathlib import Path

import pytest

from src.ml_classifier import classify_email, load_model


class ReversedClassModel:
    # PHISHING is first: inference must use classes_, not assume column 1.
    classes_ = [1, 0]

    def __init__(self, probability):
        self.probability = probability
        self.seen = None

    def predict_proba(self, texts):
        self.seen = texts
        return [[self.probability, 1 - self.probability]]


@pytest.mark.parametrize("probability,label", [(0.49, "LEGITIMATE"), (0.50, "PHISHING")])
def test_class_order_and_threshold_boundary(probability, label):
    model = ReversedClassModel(probability)
    result = classify_email("Message body", model)
    assert model.seen == ["Message body"]
    assert result["phishing_probability"] == probability
    assert result["label"] == label
    assert result["prediction"] == int(label == "PHISHING")


def test_custom_threshold():
    result = classify_email("Message body", ReversedClassModel(0.7), threshold=0.8)
    assert result["label"] == "LEGITIMATE"
    assert result["threshold"] == 0.8


def test_blank_input_does_not_call_model():
    result = classify_email("  ", object())
    assert result["phishing_probability"] == 0
    assert result["label"] == "LEGITIMATE"


def test_missing_model_has_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="ML model not found"):
        load_model(Path(tmp_path) / "missing.joblib")
