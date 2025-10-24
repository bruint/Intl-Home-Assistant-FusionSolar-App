"""CAPTCHA solver using ONNX model."""

import logging
import os
from pathlib import Path

try:
    import cv2
    import numpy as np
    import onnxruntime as rt
    CAPTCHA_AVAILABLE = True
except ImportError:
    CAPTCHA_AVAILABLE = False

from .ctc_decoder import decode

_LOGGER = logging.getLogger(__name__)

alphabet = ['2', '3', '4', '5', '6', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'l', 'r', 't', 'y']
blank_idx = 20

class CaptchaSolver:
    """CAPTCHA solver using ONNX model."""
    
    def __init__(self):
        """Initialize the CAPTCHA solver."""
        self.session = None
        self.model_path = None
        self._init_model()
    
    def _init_model(self):
        """Initialize the ONNX model."""
        if not CAPTCHA_AVAILABLE:
            _LOGGER.warning("CAPTCHA solving libraries not available. Install opencv-python, numpy, and onnxruntime.")
            return
        
        # Try to find the model file
        model_paths = [
            Path(__file__).parent / "models" / "captcha_huawei.onnx",
            Path(__file__).parent.parent.parent / "models" / "captcha_huawei.onnx",
            "/config/custom_components/fusion_solar_app/models/captcha_huawei.onnx"
        ]
        
        for path in model_paths:
            if path.exists():
                self.model_path = str(path)
                break
        
        if not self.model_path:
            _LOGGER.warning("CAPTCHA model file not found. CAPTCHA solving will not work.")
            return
        
        try:
            self.session = rt.InferenceSession(self.model_path, providers=['CPUExecutionProvider'])
            _LOGGER.debug("CAPTCHA solver initialized successfully")
        except Exception as e:
            _LOGGER.error("Failed to initialize CAPTCHA solver: %s", e)
            self.session = None
    
    def solve_captcha(self, img_data):
        """Solve CAPTCHA from image data."""
        if not self.session or not CAPTCHA_AVAILABLE:
            _LOGGER.warning("CAPTCHA solver not available")
            return None
        
        try:
            # Convert image data to numpy array
            if isinstance(img_data, bytes):
                img = np.frombuffer(img_data, np.uint8)
                img = cv2.imdecode(img, cv2.IMREAD_GRAYSCALE)
            elif isinstance(img_data, np.ndarray):
                img = img_data
            else:
                _LOGGER.error("Invalid image data type: %s", type(img_data))
                return None
            
            # Preprocess image
            img = self.preprocess_image(img)
            img = np.expand_dims(img, axis=0)
            
            # Run inference
            out = self.session.run(None, {"image": img.astype(np.float32), "label": None})
            
            # Decode result
            result = self.decode_batch_predictions(out[0])
            _LOGGER.debug("CAPTCHA solved: %s", result)
            return result
            
        except Exception as e:
            _LOGGER.error("Error solving CAPTCHA: %s", e)
            return None
    
    def decode_batch_predictions(self, pred):
        """Decode batch predictions using CTC decoder."""
        try:
            # Using a beam size of 10 here as the output is quite small as
            # we only have 19 characters and a string length of 4
            results = decode(pred[0], beam_size=10, blank=blank_idx)
            # Iterate over the results and get back the text
            output_text = list(map(lambda n: alphabet[n-1], results[0]))
            return ''.join(output_text)
        except Exception as e:
            _LOGGER.error("Error decoding CAPTCHA predictions: %s", e)
            return None
    
    def preprocess_image(self, img):
        """Preprocess image for CAPTCHA solving."""
        if len(img.shape) == 3:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        img = img / 255.0
        # swap axis
        img = np.swapaxes(img, 0, 1)
        img = np.expand_dims(img, axis=2)
        return img
