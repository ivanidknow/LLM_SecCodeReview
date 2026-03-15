import pickle
import base64

def _deserialize_layer1(data: bytes):
    """First internal layer: attempts to decode base64."""
    try:
        decoded = base64.b64decode(data)
        return _decode_layer2(decoded)
    except Exception:
        return {"error": "Invalid base64"}

def _decode_layer2(raw_obj: bytes):
    """Second internal layer: The actual sink."""
    # VULNERABILITY: Insecure Deserialization using pickle
    # Hidden beneath layers of abstractions
    parsed = pickle.loads(raw_obj)
    return parsed

def safe_data_processor(payload: bytes):
    """
    Supposedly safe public interface for the library.
    """
    return _deserialize_layer1(payload)
