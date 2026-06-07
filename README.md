# Safe Vault for Obsidian

Safe Vault provides a secure, AES-256-GCM encrypted sub-folder within your Obsidian vault. Protect sensitive notes, images, and data with a PIN and automatic locking.

## 🛡️ How it works (Important!)

To ensure maximum security and privacy, Safe Vault uses a **volatile folder mechanism**:

1.  **Unlocked State:** The plugin decrypts your data and creates a physical folder named `Safe Vault` in your vault. You can work with files inside normally.
2.  **Locked State:** When you lock the vault (or it auto-locks), the plugin encrypts the contents into a single binary file (`safe-vault.bin`) and **completely deletes the unencrypted `Safe Vault` folder** from your disk.
3.  **Data Safety:** Your data only exists in unencrypted form while the vault is active. **Always ensure the plugin is allowed to finish locking before closing Obsidian or syncing.**

## ✨ Features

-   **Strong Encryption:** Uses Web Crypto API (AES-256-GCM).
-   **PIN Protection:** PBKDF2-hardened password derivation.
-   **Auto-Lock:** Automatically locks and wipes unencrypted files after X minutes of inactivity.
-   **Recovery System:** 6 one-time recovery codes and a master settings backup.
-   **Brute-force Guard:** Progressive delays after failed attempts.
-   **Binary Support:** Encrypts images, PDFs, and other attachments, not just text.

## Installation

### Manual
1.  Download `main.js`, `manifest.json`, and `styles.css` (if any).
2.  Create a folder `.obsidian/plugins/safe-vault/`.
3.  Place the files inside and enable the plugin in Obsidian settings.

## ⚙️ Settings

-   **Auto-lock timer:** Set the idle time before the vault self-destructs (removes unencrypted files).
-   **PIN Requirements:** Configure minimum length and complexity.
-   **File Types:** Choose which extensions should be included in the encrypted container.

## ⚠️ Disclaimer

This plugin is provided "as is". While it uses industry-standard encryption, always keep backups of your `safe-vault.bin` and your recovery codes. The author is not responsible for data loss due to forgotten PINs or interrupted file operations.
