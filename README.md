# HybridShield — CNN Steganography educational demo

## Setup (Windows)
1. Install Python 3.10+.
2. Open terminal in this folder.
3. `python -m venv .venv`
4. `.venv\Scripts\activate`
5. `pip install -r requirements.txt`
6. Collect a folder of varied cover images (PNG/JPG) for training.
7. Train the CNN: `python train_cnn.py --images path\to\cover_images --epochs 20`
8. Run app: `python app.py`
9. Open `http://127.0.0.1:5000`

## Workflow
- Register Sender and Receiver accounts.
- Register Sender and Receiver accounts. Each account gets a P-256 ECC key pair.
- Sender signs in, selects a registered Receiver account; the receiver public key is fetched automatically from local account records.
- Sender enters message and PIN and selects a cover image. The encrypted payload records the sender and intended receiver usernames.
- Transfer the generated stego PNG and PIN to the receiver using a safe channel.
- Receiver uploads the PNG and PIN. The app fetches the sender public key automatically from the sender account record; it rejects payloads addressed to another receiver.

## Important
This version replaces the LSB carrier with a PyTorch CNN encoder/decoder and training script. **It is not ready until you train the model**; weights are not bundled because no dataset/model checkpoint was provided. The included training script is an educational starter, and it does not guarantee useful payload recovery or acceptable visual quality without testing. This payload size is limited to 512 bytes. If the app reports a decoder/header error, the trained model is not accurate enough yet.

Private keys are stored unencrypted in `data/users.json`; do not use real secrets or deploy publicly. This is a local educational prototype, not production-ready. Cloud storage is not configured.
