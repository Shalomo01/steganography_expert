#!/usr/bin/env python3
"""
Steg.py - Advanced GUI steganography (updated)

Features:
- Header with flags + seed + lengths + checksum so extraction knows exactly which transforms were used.
- Options: zlib compression, Fernet (AES-256) encryption (passphrase), Hamming(7,4) FEC,
  keyed PRNG pixel-order shuffle (payload only).
- Verbose extraction log showing step-by-step actions and Hamming corrections.
- Optional PNG metadata marker writer/reader.
- GUI using Tkinter.
"""

from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk, PngImagePlugin
import hashlib, zlib, random, base64, struct, math, sys


# Attempt to import cryptography (Fernet). If missing, encryption features will be unavailable.
try:
    from cryptography.fernet import Fernet, InvalidToken
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

APP_TITLE = " Sheild's Steg Pro (v 1.0)"
MAGIC = b"STEGX1"    # 6 bytes
VERSION = 1
# Header layout:
# MAGIC (6) + VERSION (1) + FLAGS (1) + SEED (8) + PLAIN_LEN (4) + ENC_LEN (4) + SHA256(payload_plain) (32)
HEADER_LEN = 6 + 1 + 1 + 8 + 4 + 4 + 32

# Flags
FLAG_COMPRESS = 1 << 0
FLAG_ENCRYPT  = 1 << 1
FLAG_HAMMING  = 1 << 2
FLAG_PRNG     = 1 << 3


# ----------------- Bit helpers -----------------
def bytes_to_bits(data: bytes) -> list:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits: list) -> bytes:
    if len(bits) % 8 != 0:
        # pad with zeros
        bits = bits + [0] * (8 - (len(bits) % 8))
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for bit in bits[i:i+8]:
            val = (val << 1) | (bit & 1)
        out.append(val)
    return bytes(out)

# ----------------- Hamming (7,4) with correction count -----------------
def _hamming_encode_4(nibble_bits):
    d1, d2, d3, d4 = nibble_bits
    p1 = (d1 ^ d2 ^ d4) & 1
    p2 = (d1 ^ d3 ^ d4) & 1
    p3 = (d2 ^ d3 ^ d4) & 1
    return [p1, p2, d1, p3, d2, d3, d4]

def _hamming_decode_7(bits7):
    # bits7 is list length 7
    b = bits7[:]  # copy
    c1 = (b[0] ^ b[2] ^ b[4] ^ b[6]) & 1
    c2 = (b[1] ^ b[2] ^ b[5] ^ b[6]) & 1
    c3 = (b[3] ^ b[4] ^ b[5] ^ b[6]) & 1
    errpos = (c3 << 2) | (c2 << 1) | c1  # 0..7
    corrected = 0
    if errpos != 0:
        idx = errpos - 1
        if 0 <= idx < 7:
            b[idx] ^= 1
            corrected = 1
    # extract d1,d2,d3,d4
    return [b[2], b[4], b[5], b[6]], corrected

def hamming_encode_bits(data_bits: list) -> list:
    out = []
    for i in range(0, len(data_bits), 4):
        nib = data_bits[i:i+4]
        if len(nib) < 4:
            nib = nib + [0] * (4 - len(nib))
        out.extend(_hamming_encode_4(nib))
    return out

def hamming_decode_bits_with_corrections(code_bits: list):
    # returns (decoded_bits_list, corrections_count)
    # trim to multiple of 7
    trim = len(code_bits) - (len(code_bits) % 7)
    code_bits = code_bits[:trim]
    decoded = []
    corrections = 0
    for i in range(0, len(code_bits), 7):
        block = code_bits[i:i+7]
        data4, corr = _hamming_decode_7(block)
        decoded.extend(data4)
        corrections += corr
    return decoded, corrections

# ----------------- Crypto (Fernet) -----------------
def derive_key_from_passphrase(passphrase: str) -> bytes:
    h = hashlib.sha256(passphrase.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(h)

def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography not installed. Install with: pip install cryptography")
    key = derive_key_from_passphrase(passphrase)
    return Fernet(key).encrypt(data)

def decrypt_bytes(data: bytes, passphrase: str) -> bytes:
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography not installed. Install with: pip install cryptography")
    key = derive_key_from_passphrase(passphrase)
    return Fernet(key).decrypt(data)

# ----------------- Header -----------------
def build_header(flags: int, seed: int, plain_len: int, enc_len: int, plain_sha: bytes) -> bytes:
    return MAGIC + bytes([VERSION]) + bytes([flags]) + seed.to_bytes(8, 'big') + struct.pack(">I", plain_len) + struct.pack(">I", enc_len) + plain_sha

def parse_header(raw: bytes):
    if len(raw) < HEADER_LEN:
        raise ValueError("Header truncated")
    if not raw.startswith(MAGIC):
        raise ValueError("MAGIC missing")
    ver = raw[6]
    flags = raw[7]
    seed = int.from_bytes(raw[8:16], 'big')
    plain_len = struct.unpack(">I", raw[16:20])[0]
    enc_len = struct.unpack(">I", raw[20:24])[0]
    sha = raw[24:56]
    return ver, flags, seed, plain_len, enc_len, sha

# ----------------- PRNG permutation -----------------
def permutation_for_positions(positions: list, seed_int: int) -> list:
    rng = random.Random(seed_int)
    perm = positions[:]
    rng.shuffle(perm)
    return perm

# ----------------- Capacity -----------------
def estimate_capacity_bits(img: Image.Image, bits_per_channel=1):
    w, h = img.size
    return w * h * 3 * bits_per_channel

# ----------------- A tool by Shalomo Jacob Agarwarkar -----------------

# ----------------- Embed / Extract -----------------
def embed_data_into_image(img: Image.Image, payload: bytes, passphrase: str|None,
                          use_compress=True, use_hamming=True, use_prng=True, bits_per_channel=1):
    if img.mode != "RGB":
        img = img.convert("RGB")
    w, h = img.size
    px = img.load()

    # compute plain sha
    plain_sha = hashlib.sha256(payload).digest()
    flags = 0

    data = payload
    if use_compress:
        data = zlib.compress(data)
        flags |= FLAG_COMPRESS

    if passphrase:
        data = encrypt_bytes(data, passphrase)
        flags |= FLAG_ENCRYPT

    enc_len = len(data)
    plain_len = len(payload)

    seed = random.getrandbits(64) if use_prng else 0
    if use_prng:
        flags |= FLAG_PRNG
    if use_hamming:
        flags |= FLAG_HAMMING

    header = build_header(flags, seed, plain_len, enc_len, plain_sha)
    header_bits = bytes_to_bits(header)

    payload_bits = bytes_to_bits(data)
    if use_hamming:
        payload_bits = hamming_encode_bits(payload_bits)

    total_bits_needed = len(header_bits) + len(payload_bits)
    capacity = estimate_capacity_bits(img, bits_per_channel)
    if total_bits_needed > capacity:
        raise ValueError(f"Not enough capacity: need {total_bits_needed} bits, have {capacity} bits.")

    coords = [(x,y,c) for y in range(h) for x in range(w) for c in range(3)]
    header_positions = coords[:len(header_bits)]
    payload_positions = coords[len(header_bits):len(header_bits) + len(payload_bits)]

    if use_prng and seed != 0:
        payload_positions = permutation_for_positions(payload_positions, seed)

    # write header bits
    for idx, bit in enumerate(header_bits):
        x,y,c = header_positions[idx]
        r,g,b = px[x,y]
        ch = [r,g,b]
        ch[c] = (ch[c] & ~1) | bit
        px[x,y] = tuple(ch)

    # write payload bits
    for idx, bit in enumerate(payload_bits):
        x,y,c = payload_positions[idx]
        r,g,b = px[x,y]
        ch = [r,g,b]
        ch[c] = (ch[c] & ~1) | bit
        px[x,y] = tuple(ch)

    return img

def extract_data_from_image(img: Image.Image, passphrase: str|None, bits_per_channel=1, scan_only=False, verbose_callback=None):
    if img.mode != "RGB":
        img = img.convert("RGB")
    w, h = img.size
    px = img.load()

    capacity = estimate_capacity_bits(img, bits_per_channel)
    needed_header_bits = HEADER_LEN * 8
    coords_all = [(x,y,c) for y in range(h) for x in range(w) for c in range(3)]

    if needed_header_bits > capacity:
        raise ValueError("Image too small to contain header.")

    # read header bits (linear)
    header_bits = []
    for pos in coords_all[:needed_header_bits]:
        x,y,c = pos
        r,g,b = px[x,y]
        header_bits.append([r&1, g&1, b&1][c])
    header_bytes = bits_to_bytes(header_bits)
    try:
        ver, flags, seed, plain_len, enc_len, sha = parse_header(header_bytes[:HEADER_LEN])
    except Exception:
        if scan_only:
            return {"has_stego": False}
        raise ValueError("Stego header not found or corrupted.")

    if verbose_callback:
        flag_list = []
        if flags & FLAG_COMPRESS: flag_list.append("compress")
        if flags & FLAG_ENCRYPT:  flag_list.append("encrypt")
        if flags & FLAG_HAMMING:  flag_list.append("hamming")
        if flags & FLAG_PRNG:     flag_list.append("prng")
        verbose_callback(f"Header found: version={ver}, flags={','.join(flag_list) or 'none'}, seed={seed}, plain_len={plain_len}, enc_len={enc_len}")

    if scan_only:
        return {"has_stego": True, "version": ver, "flags": flags, "seed": seed, "plain_len": plain_len, "encoded_len": enc_len}

    # payload bits
    payload_bits = enc_len * 8
    if flags & FLAG_HAMMING:
        groups = (payload_bits + 3) // 4
        payload_bits_embedded = groups * 7
    else:
        payload_bits_embedded = payload_bits

    total_needed = needed_header_bits + payload_bits_embedded
    if total_needed > capacity:
        raise ValueError("Image does not contain the claimed embedded payload (truncated).")

    payload_positions = coords_all[needed_header_bits:needed_header_bits + payload_bits_embedded]
    if flags & FLAG_PRNG:
        if verbose_callback: verbose_callback("Applying PRNG permutation for payload read (seed used).")
        payload_positions = permutation_for_positions(payload_positions, seed)

  # ----------------- A tool by Shalomo Jacob Agarwarkar -----------------
  # read payload bits
    payload_bits_list = []
    for pos in payload_positions:
        x,y,c = pos
        r,g,b = px[x,y]
        payload_bits_list.append([r&1, g&1, b&1][c])

    if flags & FLAG_HAMMING:
        if verbose_callback: verbose_callback("Hamming decode: attempting to correct single-bit errors.")
        decoded_bits, corrections = hamming_decode_bits_with_corrections(payload_bits_list)
        if verbose_callback: verbose_callback(f"Hamming decode complete: corrected {corrections} bit(s).")
        decoded_bits = decoded_bits[:payload_bits]  # trim to exact data bits
        payload_bytes = bits_to_bytes(decoded_bits)
    else:
        payload_bytes = bits_to_bytes(payload_bits_list)

    data = payload_bytes

    if flags & FLAG_ENCRYPT:
        if passphrase is None or passphrase == "":
            raise ValueError("Passphrase required to decrypt payload.")
        if verbose_callback: verbose_callback("Decrypting payload with provided passphrase.")
        try:
            data = decrypt_bytes(data, passphrase)
            if verbose_callback: verbose_callback("Decryption successful.")
        except Exception as e:
            raise ValueError("Decryption failed (wrong passphrase or corrupted payload).")

    if flags & FLAG_COMPRESS:
        if verbose_callback: verbose_callback("Decompressing payload (zlib).")
        try:
            data = zlib.decompress(data)
            if verbose_callback: verbose_callback("Decompression successful.")
        except Exception:
            raise ValueError("Decompression failed (corrupted payload).")

    # verify sha
    if hashlib.sha256(data).digest() != sha:
        raise ValueError("Integrity check failed: payload hash mismatch (wrong passphrase or corruption).")

    if verbose_callback: verbose_callback(f"Extraction successful: payload size {len(data)} bytes (plain).")
    return {"data": data, "version": ver, "flags": flags, "seed": seed, "plain_len": len(data), "enc_len": enc_len}

# ----------------- PNG metadata helpers -----------------
def write_png_text(in_path: Path, out_path: Path, key: str, value: str):
    img = Image.open(in_path)
    meta = PngImagePlugin.PngInfo()
    if hasattr(img, "text"):
        for k,v in img.text.items():
            meta.add_text(k, v)
    meta.add_text(key, value)
    img.save(out_path, pnginfo=meta)

def read_png_text(in_path: Path):
    img = Image.open(in_path)
    return getattr(img, "text", {})

# ----------------- GUI -----------------
class StegoApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("800x680")
        root.minsize(800,680)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_embed = ttk.Frame(self.notebook)
        self.tab_extract = ttk.Frame(self.notebook)
        self.tab_meta = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_embed, text="Embed (Stego)")
        self.notebook.add(self.tab_extract, text="Extract / Scan")
        self.notebook.add(self.tab_meta, text="PNG Metadata")

        self._build_embed_tab()
        self._build_extract_tab()
        self._build_meta_tab()

        self.preview_img = None
        self.extracted_bytes = b""
    # ----------------- A tool by Shalomo Jacob Agarwarkar -----------------

    # ---------------- Embed Tab ----------------
    def _build_embed_tab(self):
        f = self.tab_embed
        pad = {"padx": 8, "pady": 6}

        fr_in = ttk.LabelFrame(f, text="Cover Image (PNG/BMP recommended)")
        fr_in.pack(fill="x", **pad)
        self.embed_in = tk.StringVar()
        ttk.Entry(fr_in, textvariable=self.embed_in).pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(fr_in, text="Browse", command=self.browse_embed_input).pack(side="left", padx=5)

        fr_payload = ttk.LabelFrame(f, text="Payload")
        fr_payload.pack(fill="x", **pad)
        self.payload_type = tk.StringVar(value="url")
        ttk.Radiobutton(fr_payload, text="URL", variable=self.payload_type, value="url").pack(side="left")
        ttk.Radiobutton(fr_payload, text="Text", variable=self.payload_type, value="text").pack(side="left")
        ttk.Radiobutton(fr_payload, text="From file", variable=self.payload_type, value="file").pack(side="left", padx=(10,0))
        self.payload_entry = tk.Text(fr_payload, height=4)
        self.payload_entry.pack(fill="x", padx=8, pady=5)

        fr_file = ttk.Frame(fr_payload)
        fr_file.pack(fill="x", padx=8, pady=(0,6))
        ttk.Label(fr_file, text="(If 'From file') Path:").pack(side="left")
        self.payload_file = tk.StringVar()
        ttk.Entry(fr_file, textvariable=self.payload_file, width=40).pack(side="left", padx=5)
        ttk.Button(fr_file, text="Browse", command=self.browse_payload_file).pack(side="left", padx=5)

        fr_opt = ttk.LabelFrame(f, text="Options (recommended defaults ON)")
        fr_opt.pack(fill="x", **pad)
        self.var_compress = tk.BooleanVar(value=True)
        self.var_hamming = tk.BooleanVar(value=True)
        self.var_prng = tk.BooleanVar(value=True)
        ttk.Checkbutton(fr_opt, text="Compress (zlib)", variable=self.var_compress).pack(side="left", padx=4)
        ttk.Checkbutton(fr_opt, text="Hamming(7,4) FEC", variable=self.var_hamming).pack(side="left", padx=4)
        ttk.Checkbutton(fr_opt, text="Keyed PRNG pixel order (payload only)", variable=self.var_prng).pack(side="left", padx=4)
        fr_pass = ttk.Frame(fr_opt)
        fr_pass.pack(side="right", padx=6)
        ttk.Label(fr_pass, text="Passphrase (Fernet):").pack(side="left")
        self.embed_pass = tk.StringVar()
        ttk.Entry(fr_pass, textvariable=self.embed_pass, show="•", width=28).pack(side="left", padx=4)

        fr_out = ttk.LabelFrame(f, text="Output Image")
        fr_out.pack(fill="x", **pad)
        self.embed_out = tk.StringVar()
        ttk.Entry(fr_out, textvariable=self.embed_out).pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(fr_out, text="Save As", command=self.browse_embed_output).pack(side="left", padx=5)

        fr_btn = ttk.Frame(f)
        fr_btn.pack(fill="x", **pad)
        ttk.Button(fr_btn, text="Estimate Capacity", command=self.estimate_capacity).pack(side="left", padx=5)
        ttk.Button(fr_btn, text="Embed Now", command=self.do_embed).pack(side="right", padx=5)

        fr_prev = ttk.LabelFrame(f, text="Preview")
        fr_prev.pack(fill="both", expand=True, **pad)
        self.preview_label = ttk.Label(fr_prev, anchor="center")
        self.preview_label.pack(fill="both", expand=True)

        # Optional metadata marker
        fr_marker = ttk.Frame(f)
        fr_marker.pack(fill="x", **pad)
        self.marker_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(fr_marker, text="Write PNG metadata marker (key=Stego, value=1)", variable=self.marker_var).pack(side="left")

    def browse_embed_input(self):
        f = filedialog.askopenfilename(filetypes=[("Images","*.png;*.bmp;*.jpg;*.jpeg"), ("All","*.*")])
        if f:
            self.embed_in.set(f)
            self.show_preview(Path(f))

    def browse_payload_file(self):
        f = filedialog.askopenfilename()
        if f:
            self.payload_file.set(f)

    def browse_embed_output(self):
        f = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png"), ("BMP","*.bmp")])
        if f:
            self.embed_out.set(f)

    def show_preview(self, path: Path):
        try:
            img = Image.open(path)
            img = img.convert("RGB")
            maxw, maxh = 760, 240
            w,h = img.size
            scale = min(maxw/w, maxh/h, 1.0)
            new = img.resize((int(w*scale), int(h*scale)))
            self.preview_img = ImageTk.PhotoImage(new)
            self.preview_label.configure(image=self.preview_img)
        except Exception as e:
            self.preview_label.configure(text=f"Preview error: {e}")

    def estimate_capacity(self):
        try:
            p = Path(self.embed_in.get())
            if not p.exists():
                messagebox.showerror("Error", "Select a cover image.")
                return
            img = Image.open(p).convert("RGB")
            cap_bits = estimate_capacity_bits(img, 1)
            cap_bytes = cap_bits // 8
            messagebox.showinfo("Capacity", f"Approx capacity (1 bit/channel): {cap_bits} bits (~{cap_bytes} bytes).")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _gather_payload_bytes(self):
        mode = self.payload_type.get()
        if mode == "file":
            pf = self.payload_file.get().strip()
            if not pf:
                raise ValueError("Select a payload file.")
            with open(pf, "rb") as fh:
                return fh.read()
        else:
            text = self.payload_entry.get("1.0", "end").strip()
            if not text:
                raise ValueError("Enter URL/Text payload.")
            return text.encode("utf-8")

    def do_embed(self):
        try:
            in_path = Path(self.embed_in.get())
            out_path = Path(self.embed_out.get())
            if not in_path.exists():
                messagebox.showerror("Error", "Cover image not found.")
                return
            if not out_path:
                messagebox.showerror("Error", "Choose an output filename.")
                return
            payload = self._gather_payload_bytes()
            img = Image.open(in_path)
            res_img = embed_data_into_image(
                img=img,
                payload=payload,
                passphrase=(self.embed_pass.get().strip() or None),
                use_compress=self.var_compress.get(),
                use_hamming=self.var_hamming.get(),
                use_prng=self.var_prng.get(),
                bits_per_channel=1
            )
            # Save lossless (default to PNG)
            ext = out_path.suffix.lower()
            if ext not in (".png", ".bmp"):
                out_path = out_path.with_suffix(".png")
            # If user requested marker, write via PngImagePlugin
            if self.marker_var.get() and out_path.suffix.lower() == ".png":
                # Save to bytes and then write metadata
                meta = PngImagePlugin.PngInfo()
                meta.add_text("Stego", "1")
                res_img.save(out_path, format="PNG", pnginfo=meta)
            else:
                res_img.save(out_path, format="PNG" if out_path.suffix.lower()==".png" else "BMP")
            messagebox.showinfo("Success", f"Embedded payload into:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Embed Error", str(e))

    # ----------------- Extract Tab -----------------
    def _build_extract_tab(self):
        f = self.tab_extract
        pad = {"padx": 8, "pady": 6}

        fr_in = ttk.LabelFrame(f, text="Stego Image")
        fr_in.pack(fill="x", **pad)
        self.ext_in = tk.StringVar()
        ttk.Entry(fr_in, textvariable=self.ext_in).pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(fr_in, text="Browse", command=self.browse_extract_input).pack(side="left", padx=5)

        fr_pass = ttk.Frame(f)
        fr_pass.pack(fill="x", **pad)
        ttk.Label(fr_pass, text="Passphrase (if used):").pack(side="left")
        self.ext_pass = tk.StringVar()
        ttk.Entry(fr_pass, textvariable=self.ext_pass, show="•", width=30).pack(side="left", padx=6)

        fr_btn = ttk.Frame(f)
        fr_btn.pack(fill="x", **pad)
        ttk.Button(fr_btn, text="Scan (show header)", command=self.do_scan).pack(side="left", padx=5)
        ttk.Button(fr_btn, text="Extract (with log)", command=self.do_extract).pack(side="left", padx=5)
        ttk.Button(fr_btn, text="Save Extracted to File", command=self.save_extracted).pack(side="right", padx=5)

        fr_out = ttk.LabelFrame(f, text="Verbose Log & Extracted")
        fr_out.pack(fill="both", expand=True, **pad)

        self.log_text = tk.Text(fr_out, height=12, wrap="word")
        self.log_text.pack(fill="both", expand=False, padx=6, pady=6)

        ttk.Separator(fr_out).pack(fill="x", pady=(2,6))

        ttk.Label(fr_out, text="Extracted payload (preview)").pack(anchor="w", padx=6)
        self.extract_text = tk.Text(fr_out, height=10, wrap="word")
        self.extract_text.pack(fill="both", expand=True, padx=6, pady=6)

    def browse_extract_input(self):
        f = filedialog.askopenfilename(filetypes=[("Images","*.png;*.bmp;*.jpg;*.jpeg"), ("All","*.*")])
        if f:
            self.ext_in.set(f)

    def _log(self, s: str):
        self.log_text.insert("end", s + "\n")
        self.log_text.see("end")

    def do_scan(self):
        self.log_text.delete("1.0", "end")
        try:
            p = Path(self.ext_in.get())
            if not p.exists():
                messagebox.showerror("Error", "Select an image.")
                return
            img = Image.open(p)
            info = extract_data_from_image(img, passphrase=(self.ext_pass.get().strip() or None), scan_only=True)
            if info.get("has_stego"):
                flags = info["flags"]
                details = []
                if flags & FLAG_COMPRESS: details.append("compressed")
                if flags & FLAG_ENCRYPT:  details.append("encrypted")
                if flags & FLAG_HAMMING:  details.append("hamming")
                if flags & FLAG_PRNG:     details.append("prng")
                self._log("Stego header detected:")
                self._log(f"  Version: {info['version']}")
                self._log(f"  Flags: {', '.join(details) or 'none'}")
                self._log(f"  Plain payload length (bytes): {info['plain_len']}")
                self._log(f"  Encoded payload length (bytes): {info['encoded_len']}")
                self._log(f"  Seed (for PRNG): {info['seed']}")
                messagebox.showinfo("Scan", "Stego header found. See verbose log for details.")
            else:
                self._log("No stego header detected.")
                messagebox.showinfo("Scan", "No stego header detected.")
        except Exception as e:
            self._log(f"Scan Error: {e}")
            messagebox.showerror("Scan Error", str(e))

    def do_extract(self):
        self.log_text.delete("1.0", "end")
        self.extract_text.delete("1.0", "end")
        try:
            p = Path(self.ext_in.get())
            if not p.exists():
                messagebox.showerror("Error", "Select an image.")
                return
            img = Image.open(p)
            def verbose_cb(msg):
                self._log(msg)
            result = extract_data_from_image(img, passphrase=(self.ext_pass.get().strip() or None), scan_only=False, verbose_callback=verbose_cb)
            self.extracted_bytes = result["data"]
            preview = self._safe_preview(self.extracted_bytes)
            self.extract_text.insert("1.0", preview)
            messagebox.showinfo("Success", f"Extracted {len(self.extracted_bytes)} bytes. See verbose log for details.")
        except Exception as e:
            self._log(f"Extract Error: {e}")
            messagebox.showerror("Extract Error", str(e))

    def save_extracted(self):
        if not getattr(self, "extracted_bytes", b""):
            messagebox.showerror("Nothing to save", "Run Extract first.")
            return
        f = filedialog.asksaveasfilename()
        if f:
            with open(f, "wb") as fh:
                fh.write(self.extracted_bytes)
            messagebox.showinfo("Saved", f"Saved extracted data to:\n{f}")

    def _safe_preview(self, b: bytes) -> str:
        try:
            s = b.decode("utf-8")
            if len(s) > 8000:
                return s[:8000] + "\n...[truncated preview]..."
            return s
        except Exception:
            return f"[binary data: {len(b)} bytes]\n(Use 'Save Extracted to File')"

    # ----------------- Metadata Tab -----------------
    def _build_meta_tab(self):
        f = self.tab_meta
        pad = {"padx": 8, "pady": 6}

        fr_w = ttk.LabelFrame(f, text="Write URL to PNG text chunk")
        fr_w.pack(fill="x", **pad)
        self.meta_in = tk.StringVar()
        self.meta_out = tk.StringVar()
        self.meta_key = tk.StringVar(value="URL")
        self.meta_val = tk.StringVar()

        row1 = ttk.Frame(fr_w); row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Input PNG:").pack(side="left")
        ttk.Entry(row1, textvariable=self.meta_in).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(row1, text="Browse", command=lambda:self._browse_file(self.meta_in, [("PNG","*.png")])).pack(side="left", padx=5)

        row2 = ttk.Frame(fr_w); row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Output PNG:").pack(side="left")
        ttk.Entry(row2, textvariable=self.meta_out).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(row2, text="Save As", command=lambda:self._browse_save(self.meta_out, ".png")).pack(side="left", padx=5)

        row3 = ttk.Frame(fr_w); row3.pack(fill="x", pady=4)
        ttk.Label(row3, text="Key:").pack(side="left")
        ttk.Entry(row3, textvariable=self.meta_key, width=10).pack(side="left", padx=5)
        ttk.Label(row3, text="Value (URL):").pack(side="left", padx=(12,0))
        ttk.Entry(row3, textvariable=self.meta_val, width=40).pack(side="left", padx=5)
        ttk.Button(fr_w, text="Write Metadata", command=self.do_meta_write).pack(pady=6)

        fr_r = ttk.LabelFrame(f, text="Read PNG text metadata")
        fr_r.pack(fill="both", expand=True, **pad)
        self.meta_read_in = tk.StringVar()
        row4 = ttk.Frame(fr_r); row4.pack(fill="x", pady=4)
        ttk.Label(row4, text="PNG:").pack(side="left")
        ttk.Entry(row4, textvariable=self.meta_read_in).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(row4, text="Browse", command=lambda:self._browse_file(self.meta_read_in, [("PNG","*.png")])).pack(side="left", padx=5)

        self.meta_text = tk.Text(fr_r, wrap="word")
        self.meta_text.pack(fill="both", expand=True, padx=6, pady=6)
        ttk.Button(fr_r, text="Read Metadata", command=self.do_meta_read).pack(pady=6)

    def _browse_file(self, var: tk.StringVar, types):
        f = filedialog.askopenfilename(filetypes=types)
        if f:
            var.set(f)

    def _browse_save(self, var: tk.StringVar, defext):
        f = filedialog.asksaveasfilename(defaultextension=defext)
        if f:
            var.set(f)

    def do_meta_write(self):
        try:
            if not self.meta_in.get() or not self.meta_out.get():
                messagebox.showerror("Error", "Select input and output PNG.")
                return
            write_png_text(Path(self.meta_in.get()), Path(self.meta_out.get()), self.meta_key.get() or "URL", self.meta_val.get())
            messagebox.showinfo("Done", f"Wrote metadata to {self.meta_out.get()}")
        except Exception as e:
            messagebox.showerror("Metadata Error", str(e))

    def do_meta_read(self):
        try:
            if not self.meta_read_in.get():
                messagebox.showerror("Error", "Select a PNG.")
                return
            meta = read_png_text(Path(self.meta_read_in.get()))
            self.meta_text.delete("1.0", "end")
            if not meta:
                self.meta_text.insert("1.0", "(No PNG text metadata found)")
            else:
                for k,v in meta.items():
                    self.meta_text.insert("end", f"{k} = {v}\n")
        except Exception as e:
            messagebox.showerror("Metadata Error", str(e))

# ----------------- main -----------------
if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    app = StegoApp(root)
    root.mainloop()
