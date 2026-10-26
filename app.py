
import os
import json
import secrets
import hashlib
import hmac

from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file
)
from PIL import Image
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20_Poly1305

from ecc import generate_keypair, derive_shared_key
from cnn_steganography import embed_cnn_payload, extract_cnn_payload
from google_drive import upload_file

# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

BASE = os.path.dirname(os.path.abspath(__file__))

for folder in ("data", "uploads", "outputs"):
    os.makedirs(os.path.join(BASE, folder), exist_ok=True)

UF = os.path.join(BASE, "data", "users.json")

app = Flask(__name__)
app.secret_key = (
    os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
)
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024

AAD = b"HybridDataSecurity-v1"


# --------------------------------------------------
# USER DATABASE
# --------------------------------------------------

def users():
    try:
        with open(UF, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save(user_data):
    temp_file = UF + ".tmp"

    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2)

    os.replace(temp_file, UF)


# --------------------------------------------------
# PASSWORD HASHING
# --------------------------------------------------

def pwrec(password):
    salt = get_random_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        300000
    ).hex()

    return {
        "salt": salt.hex(),
        "hash": password_hash
    }


def pwok(password, record):
    try:
        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(record["salt"]),
            300000
        ).hex()

        return hmac.compare_digest(
            calculated_hash,
            record["hash"]
        )

    except (KeyError, ValueError, TypeError):
        return False


# --------------------------------------------------
# CURRENT USER AND ACCESS CONTROL
# --------------------------------------------------

def me():
    return users().get(session.get("username", ""))


def need(role):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if (
                not session.get("username")
                or session.get("role") != role
            ):
                flash("Please sign in to the correct portal.", "error")
                return redirect(url_for("login", role=role))

            return function(*args, **kwargs)

        return wrapper

    return decorator


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html")


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route("/register/<role>", methods=["GET", "POST"])
def register(role):
    if role not in ("sender", "receiver"):
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        user_data = users()

        if not name or len(password) < 8:
            flash(
                "Enter a username and password of at least 8 characters.",
                "error"
            )

        elif password != confirm_password:
            flash("Passwords do not match.", "error")

        elif name in user_data:
            flash("Username already exists.", "error")

        else:
            private_key, public_key = generate_keypair()

            user_data[name] = {
                "role": role,
                "password": pwrec(password),
                "private_key": private_key,
                "public_key": public_key
            }

            save(user_data)

            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login", role=role))

    return render_template("register.html", role=role)


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login/<role>", methods=["GET", "POST"])
def login(role):
    if role not in ("sender", "receiver"):
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user_data = users().get(name)

        if (
            user_data
            and user_data.get("role") == role
            and pwok(password, user_data.get("password", {}))
        ):
            session.clear()
            session.update(username=name, role=role)

            return redirect(url_for(role))

        flash("Invalid username or password.", "error")

    return render_template("login.html", role=role)


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# --------------------------------------------------
# PUBLIC KEY PAGE
# --------------------------------------------------

@app.route("/keys")
def keys():
    if not session.get("username"):
        return redirect(url_for("home"))

    account = me()

    if not account:
        session.clear()
        return redirect(url_for("home"))

    return render_template(
        "keys.html",
        public_key=account["public_key"],
        username=session["username"],
        role=session["role"]
    )


# --------------------------------------------------
# SENDER WORKSPACE
# --------------------------------------------------

@app.route("/sender", methods=["GET", "POST"])
@need("sender")
def sender():

    if request.method == "POST":
        message = request.form.get("message", "")
        pin = request.form.get("pin", "")
        receiver_name = request.form.get(
            "receiver_username", ""
        ).strip()
        cover = request.files.get("cover")

        account_book = users()
        receiver_account = account_book.get(receiver_name)

        if (
            not message.strip()
            or len(pin) < 4
            or not receiver_name
            or not receiver_account
            or receiver_account.get("role") != "receiver"
            or not cover
            or not cover.filename
        ):
            flash(
                "Message, PIN, valid receiver account and cover image are required.",
                "error"
            )
            return redirect(url_for("sender"))

        peer = receiver_account["public_key"]
        cover_path = None

        try:
            # Validate uploaded cover image
            with Image.open(cover.stream) as image:
                image.verify()

            cover.stream.seek(0)

            cover_path = os.path.join(
                BASE,
                "uploads",
                secrets.token_hex(8) + ".png"
            )

            with Image.open(cover.stream) as image:
                image.convert("RGB").save(cover_path, "PNG")

            # Derive ECC shared key
            salt = get_random_bytes(16)

            key = derive_shared_key(
                me()["private_key"],
                peer,
                salt
            )

            # Encrypt message using ChaCha20-Poly1305
            cipher = ChaCha20_Poly1305.new(key=key)
            cipher.update(AAD)

            plaintext = message.encode("utf-8")
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

            # Hash PIN
            pin_salt = get_random_bytes(16)

            pin_hash = hashlib.pbkdf2_hmac(
                "sha256",
                pin.encode(),
                pin_salt,
                200000
            ).hex()

            # Prepare encrypted payload metadata
            metadata = {
                "version": 1,
                "sender": session["username"],
                "receiver": receiver_name,
                "salt": salt.hex(),
                "nonce": cipher.nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
                "pin_salt": pin_salt.hex(),
                "pin_hash": pin_hash,
                "message_hash": hashlib.sha256(
                    plaintext
                ).hexdigest()
            }

            # Embed encrypted payload in cover image
            filename = "stego_" + secrets.token_hex(6) + ".png"
            output_path = os.path.join(BASE, "outputs", filename)

            embed_cnn_payload(
                cover_path,
                output_path,
                json.dumps(
                    metadata,
                    separators=(",", ":")
                ).encode("utf-8")
            )

            session["last_output"] = filename

            # Upload to Google Drive without blocking local output
            drive_result = None
            drive_error = None

            try:
                drive_result = upload_file(output_path)
            except Exception as e:
                drive_error = str(e)
                app.logger.exception("Google Drive upload failed")

            return render_template(
                "success.html",
                filename=filename,
                hash_value=metadata["message_hash"],
                drive_link=(
                    drive_result.get("webViewLink")
                    if drive_result else None
                ),
                drive_file_id=(
                    drive_result.get("id")
                    if drive_result else None
                ),
                drive_error=drive_error
            )

        except Exception as error:
            app.logger.exception("Sender processing failed")
            flash(
                "Could not encrypt/embed. Check receiver account, ECC key and image. "
                + str(error),
                "error"
            )
            return redirect(url_for("sender"))

        finally:
            if cover_path and os.path.exists(cover_path):
                os.remove(cover_path)

    receiver_names = sorted(
        name
        for name, account in users().items()
        if account.get("role") == "receiver"
    )

    return render_template(
        "sender.html",
        username=session["username"],
        receiver_names=receiver_names
    )


# --------------------------------------------------
# VIEW GENERATED STEGO IMAGE
# --------------------------------------------------

@app.route("/outputs/<path:filename>")
@need("sender")
def output_image(filename):
    if filename != session.get("last_output"):
        return redirect(url_for("sender"))

    file_path = os.path.join(BASE, "outputs", filename)

    if not os.path.isfile(file_path):
        flash("Output image not found.", "error")
        return redirect(url_for("sender"))

    return send_file(file_path, mimetype="image/png")


# --------------------------------------------------
# DOWNLOAD GENERATED STEGO IMAGE
# --------------------------------------------------

@app.route("/download/<path:filename>")
@need("sender")
def download(filename):
    if filename != session.get("last_output"):
        return redirect(url_for("sender"))

    file_path = os.path.join(BASE, "outputs", filename)

    if not os.path.isfile(file_path):
        flash("Output image not found.", "error")
        return redirect(url_for("sender"))

    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename,
        mimetype="image/png"
    )


# --------------------------------------------------
# RECEIVER WORKSPACE
# --------------------------------------------------

@app.route("/receiver", methods=["GET", "POST"])
@need("receiver")
def receiver():

    all_users = users()

    sender_public_keys = {
        name: account["public_key"]
        for name, account in all_users.items()
        if account.get("role") == "sender"
        and account.get("public_key")
    }

    sender_names = sorted(sender_public_keys.keys())

    if request.method == "POST":
        f = request.files.get("stego")
        pin = request.form.get("pin", "")
        selected_sender = request.form.get(
            "sender_public_key", ""
        ).strip()

        path = None

        if not f or not f.filename or not pin or not selected_sender:
            flash("Choose image, sender and PIN.", "error")
            return redirect(url_for("receiver"))

        try:
            with Image.open(f.stream) as im:
                im.verify()

            f.stream.seek(0)

            path = os.path.join(
                BASE, "uploads",
                "recv_" + secrets.token_hex(8) + ".png"
            )

            with Image.open(f.stream) as im:
                im.convert("RGB").save(path, "PNG")

            m = json.loads(extract_cnn_payload(path).decode())

            if m.get("version") != 1:
                raise ValueError("Unsupported payload version.")

            if m.get("receiver") != session["username"]:
                raise ValueError("Wrong receiver account.")

            actual_sender = m.get("sender", "")

            if actual_sender != selected_sender:
                raise ValueError("Selected sender does not match this image.")

            sender_account = all_users.get(actual_sender)

            if not sender_account or sender_account.get("role") != "sender":
                raise ValueError("Sender account/public key not found.")

            peer = sender_account["public_key"]

            actual = hashlib.pbkdf2_hmac(
                "sha256",
                pin.encode(),
                bytes.fromhex(m["pin_salt"]),
                200000
            ).hex()

            if not hmac.compare_digest(actual, m["pin_hash"]):
                raise ValueError("Incorrect PIN.")

            key = derive_shared_key(
                me()["private_key"],
                peer,
                bytes.fromhex(m["salt"])
            )

            cipher = ChaCha20_Poly1305.new(
                key=key,
                nonce=bytes.fromhex(m["nonce"])
            )
            cipher.update(AAD)

            plain = cipher.decrypt_and_verify(
                bytes.fromhex(m["ciphertext"]),
                bytes.fromhex(m["tag"])
            )

            digest = hashlib.sha256(plain).hexdigest()

            if not hmac.compare_digest(digest, m["message_hash"]):
                raise ValueError("SHA-256 mismatch.")

            return render_template(
                "receiver_result.html",
                message=plain.decode("utf-8"),
                digest=digest,
                sender=actual_sender
            )

        except Exception as e:
            app.logger.exception("Receiver verification failed")
            flash("Verification/decryption failed: " + str(e), "error")
            return redirect(url_for("receiver"))

        finally:
            if path and os.path.exists(path):
                os.remove(path)

    return render_template(
        "receiver.html",
        username=session["username"],
        sender_names=sender_names,
        sender_public_keys=sender_public_keys
    )


# --------------------------------------------------
# ABOUT PAGE
# --------------------------------------------------

@app.route("/about")
def about():
    return render_template("about.html")


# --------------------------------------------------
# FILE SIZE ERROR
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(_error):
    return "File too large; maximum size is 15 MB.", 413


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
