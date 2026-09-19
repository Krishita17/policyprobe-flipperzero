"""Device-type identification and weak-implementation flagging."""

from .features import FEATURE_NAMES, extract_features
from .model import WeaknessClassifier

__all__ = ["FEATURE_NAMES", "extract_features", "WeaknessClassifier"]
