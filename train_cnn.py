
"""
train_cnn.py
HybridShield CNN Steganography - Verification Script

Note:
The current cnn_steganography.py uses a fixed convolution layer.
No dataset, training, or model weights are required.
This script verifies that embedding and extraction work.
"""

import os
import sys
import tempfile

from PIL import Image

from cnn_steganography import (
    embed_cnn_payload,
    extract_cnn_payload,
)


def main():
    print("=" * 55)
    print(" HybridShield CNN Steganography Verification")
    print("=" * 55)

    # Create a temporary test image.
    # This is only for testing, not for training.
    with tempfile.TemporaryDirectory() as temp_dir:
        input_image = os.path.join(temp_dir, "test_cover.png")
        output_image = os.path.join(temp_dir, "test_stego.png")

        image = Image.new("RGB", (1024, 1024))

        # Generate a simple image with pixel variation.
        pixels = image.load()
        for y in range(image.height):
            for x in range(image.width):
                pixels[x, y] = (
                    (x + y) % 256,
                    (2 * x + y) % 256,
                    (x + 2 * y) % 256,
                )

        image.save(input_image, format="PNG")

        test_payload = (
            b"HybridShield steganography test successful."
        )

        try:
            embed_cnn_payload(
                input_image,
                output_image,
                test_payload,
            )

            extracted_payload = extract_cnn_payload(
                output_image
            )

            if extracted_payload == test_payload:
                print("[SUCCESS] Payload embedded and extracted.")
                print("[SUCCESS] Payload verification passed.")
                print("No trained model or weights were needed.")
            else:
                print("[FAILED] Extracted payload does not match.")
                sys.exit(1)

        except Exception as error:
            print("[FAILED]", error)
            sys.exit(1)

    print("=" * 55)


if __name__ == "__main__":
    main()
