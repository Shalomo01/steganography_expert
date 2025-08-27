# steganography_expert
A world class stego tool that helps you to hide any kind of data

🛡️ Shield's Steg Pro (v1.0)
An advanced steganography toolkit with GUI built in Python.
<img width="801" height="708" alt="image" src="https://github.com/user-attachments/assets/5eb76ce5-b51b-488e-8d27-2b47578a05d2" />


Easily embed and extract hidden data (text, URLs, or files) inside images using robust techniques such as compression, encryption, error correction, and keyed pixel shuffling.
	 Features
•	🔒 AES-256 encryption (Fernet) – protect payloads with a passphrase.
•	🗜️ Zlib compression – shrink payloads before embedding.
•	🧮 Hamming (7,4) error correction – detect & fix single-bit errors during extraction.
•	🎲 Keyed PRNG pixel order shuffle – payload bits are scattered based on a random seed.
•	🖼️ Supports PNG & BMP (lossless formats recommended).
•	📝 PNG metadata embedding/reading – store extra data in PNG text chunks.
•	🖥️ Tkinter GUI with three main tabs:
o	Embed (Stego) – hide your data.
o	Extract / Scan – detect and recover payloads with verbose logs.
o	PNG Metadata – write or read metadata in PNG files.
•	✅ Integrity check with SHA-256 of payload.
•	📊 Capacity estimator to check max payload size per image.
	 Requirements
•	Python 3.8+
•	Install dependencies:
	requirements.txt
•	pillow
•	cryptography

	Embed (Stego)
1.	Choose a cover image (PNG/BMP recommended).
2.	Select payload type:
o	URL
o	Text
o	File (any binary file)
3.	(Optional) Provide a passphrase for encryption.
4.	Toggle options:
o	Compress
o	Hamming(7,4) error correction
o	Keyed PRNG pixel order
5.	Choose output filename.
6.	Click Embed Now.
7.	(Optional) Add PNG metadata marker (Stego=1).
Result: New image file containing hidden payload.

	Extract / Scan
1.	Load a stego image.
2.	Enter passphrase (if encryption was used).
3.	Choose:
o	Scan → only detect header and payload info.
o	Extract → fully recover the payload with verbose logs.
4.	Save extracted data as a file if needed.
Verbose log shows:
•	Header details (flags, version, seed, lengths).
•	Steps performed (decryption, decompression, error corrections).
•	Warnings if corruption or wrong passphrase detected.
	PNG Metadata
•	Write: Add key/value pairs (e.g., URL=https://example.com) into PNG text chunks.
•	Read: Extract and display all text metadata from PNG images.

	Sample Workflow
•	Hide a secret.txt file inside a cover.png with encryption:
1.	Select cover.png.
2.	Payload → From file → secret.txt.
3.	Enter passphrase → MyStrongPass123.
4.	Enable compression + hamming + PRNG.
5.	Save as stego.png.
•	Extract later:
1.	Open stego.png.
2.	Enter same passphrase.
3.	Click Extract.
4.	Save recovered file.
	Notes & Limitations
•	Use lossless formats (PNG/BMP) to avoid corruption.
•	JPEG is supported but lossy compression may destroy hidden data.
•	Extraction requires the exact same passphrase and settings used during embedding.
•	Very large payloads may exceed image capacity – check with Estimate Capacity.

