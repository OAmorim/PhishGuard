from pathlib import Path

import joblib


MODEL_PATH = Path("models/phishing_model.joblib")

DEFAULT_THRESHOLD = 0.50


def load_model(model_path=MODEL_PATH):
    """
    Load the trained phishing classification model.
    """

    if not model_path.exists():
        raise FileNotFoundError(
            f"ML model not found at: {model_path}"
        )

    return joblib.load(model_path)


def classify_email(
    text,
    model,
    threshold=DEFAULT_THRESHOLD,
):
    """
    Classify an email using the trained ML model.
    """

    if not text or not text.strip():
        return {
            "phishing_probability": 0.0,
            "prediction": 0,
            "label": "LEGITIMATE",
            "threshold": threshold,
        }

    probabilities = model.predict_proba(
        [text]
    )[0]

    classes = list(model.classes_)

    phishing_index = classes.index(1)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    prediction = int(
        phishing_probability >= threshold
    )

    label = (
        "PHISHING"
        if prediction == 1
        else "LEGITIMATE"
    )

    return {
        "phishing_probability": phishing_probability,
        "prediction": prediction,
        "label": label,
        "threshold": threshold,
    }