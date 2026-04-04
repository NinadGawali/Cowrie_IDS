import os
import importlib
from typing import Dict, Any, List, Optional

try:
    joblib = importlib.import_module("joblib")
except Exception:  # pragma: no cover
    joblib = None


MODEL_PATH = os.getenv("MODEL_PATH", "/app/model_training/model.pkl")


class AttackClassifier:
    def __init__(self, model_path: str = MODEL_PATH) -> None:
        self.model_path = model_path
        self._model = None
        self._error: Optional[str] = None
        self._load_model()

    @staticmethod
    def extract_features(cmd: str) -> List[int]:
        cmd = (cmd or "").lower()
        return [
            len(cmd),
            int("wget" in cmd),
            int("curl" in cmd),
            int("cat" in cmd),
            int("sudo" in cmd),
            int("chmod" in cmd),
            int("nc" in cmd),
            int("bash" in cmd or "sh" in cmd),
            int("/etc/passwd" in cmd),
            int("crontab" in cmd or "@reboot" in cmd),
            int("python" in cmd or "perl" in cmd or "php" in cmd),
            cmd.count(" "),
            cmd.count("/"),
        ]

    def _load_model(self) -> None:
        if joblib is None:
            self._error = "joblib is not installed"
            return
        if not os.path.exists(self.model_path):
            self._error = f"Model not found at {self.model_path}"
            return
        try:
            self._model = joblib.load(self.model_path)
            self._error = None
        except Exception as exc:
            self._error = f"Failed to load model: {exc}"
            self._model = None

    def classify_command(self, command: Optional[str]) -> Dict[str, Any]:
        if not command:
            return {
                "attack_label": "no_command",
                "attack_confidence": None,
                "model_available": self.available,
            }

        if self._model is None:
            return {
                "attack_label": "model_unavailable",
                "attack_confidence": None,
                "model_available": False,
                "model_error": self._error,
            }

        feats = self.extract_features(command)
        try:
            pred = self._model.predict([feats])[0]
            confidence = None
            if hasattr(self._model, "predict_proba"):
                probs = self._model.predict_proba([feats])[0]
                confidence = float(max(probs))
            return {
                "attack_label": str(pred),
                "attack_confidence": confidence,
                "model_available": True,
            }
        except Exception as exc:
            return {
                "attack_label": "prediction_error",
                "attack_confidence": None,
                "model_available": False,
                "model_error": str(exc),
            }

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def error(self) -> Optional[str]:
        return self._error
