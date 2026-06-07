'use strict';

const { Plugin, Notice, PluginSettingTab, Setting, Modal, Platform } = require('obsidian');

//  Safe Vault — Obsidian Plugin
//  AES-256-GCM encrypted folder in your vault.
//  PIN-protected, auto-locks on inactivity.

const VAULT_FILE   = 'safe-vault.bin';
const VAULT_FOLDER = 'Safe Vault';

const DEFAULT_SETTINGS = {
    pinHash:          null,
    salt:             null,
    pinSalt:          null,
    failedAttempts:   0,
    lastAttemptTime:  0,
    autoLockMinutes:  5,
    minPinLength:     6,
    requireLetters:   true,
    requireNumbers:   true,
    recoveryCodes:    [],
    errors:           [],
    supportedExts:    ['md','txt','json','css','js','html','xml','svg',
    'png','jpg','jpeg','gif','webp','pdf',
    'doc','docx','xls','xlsx','zip','7z','rar'],
};

module.exports = class SafeVaultPlugin extends Plugin {

    // ── Lifecycle

    async onload() {
        this.isUnlocked = false;
        this._key       = null;          // CryptoKey, only while unlocked
        this._autoTimer = null;
        this._lastActivity = Date.now();

        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        await this._ensureSalts();

        // Ribbon button
        this.ribbonEl = this.addRibbonIcon('shield', 'Safe Vault', () => {
            this.isUnlocked ? this._lockVault() : this._showLockModal();
        });
        this._updateRibbon();

        // Commands (registered via Obsidian API — no global keydown listener)
        this.addCommand({
            id:   'toggle-vault',
            name: 'Lock / Unlock Safe Vault',
            callback: () => this.isUnlocked ? this._lockVault() : this._showLockModal(),
        });
        this.addCommand({
            id:   'lock-vault',
            name: 'Lock Safe Vault now',
            callback: () => this._lockVault(),
        });

        this.addSettingTab(new SafeVaultSettingTab(this.app, this));

        // Auto-save on file change inside the vault folder
        this.registerEvent(this.app.vault.on('modify', (file) => {
            if (this.isUnlocked && file.path.startsWith(VAULT_FOLDER + '/')) {
                this._saveToVault();
                this._bumpActivity();
            }
        }));

        // Track activity for auto-lock
        this.registerDomEvent(document, 'mousemove', () => this._bumpActivity());
        this.registerDomEvent(document, 'keydown',   () => this._bumpActivity());
        this.registerDomEvent(document, 'click',     () => this._bumpActivity());
        this.registerDomEvent(document, 'touchstart',() => this._bumpActivity());

        this._startAutoLockTimer();

        // Show lock screen when layout is ready (if PIN is configured)
        this.app.workspace.onLayoutReady(() => {
            if (this.settings.pinHash) this._showLockModal();
        });
    }

    async onunload() {
        if (this._autoTimer) clearInterval(this._autoTimer);
        this._key = null;
        await this._cleanupFolder();
    }

    // ── Salts

    async _ensureSalts() {
        let changed = false;
        if (!this.settings.salt) {
            this.settings.salt = Array.from(crypto.getRandomValues(new Uint8Array(32)));
            changed = true;
        }
        if (!this.settings.pinSalt) {
            this.settings.pinSalt = Array.from(crypto.getRandomValues(new Uint8Array(32)));
            changed = true;
        }
        if (changed) await this.saveData(this.settings);
    }

    // ── Crypto

    async _hashPin(pin) {
        const salt = new Uint8Array(this.settings.pinSalt);
        const km   = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, km, 256);
        return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
    }

    async _verifyPin(pin) {
        return (await this._hashPin(pin)) === this.settings.pinHash;
    }

    async _deriveKey(pin) {
        const salt = new Uint8Array(this.settings.salt);
        const km   = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
            km,
            { name: 'AES-GCM', length: 256 },
            false, ['encrypt','decrypt']);
    }

    // ── Brute-force guard

    async _checkBruteForce() {
        const { failedAttempts, lastAttemptTime } = this.settings;
        if (failedAttempts >= 5) {
            const elapsed = (Date.now() - lastAttemptTime) / 1000;
            if (elapsed < 300) {
                const wait = Math.ceil((300 - elapsed) / 60);
                throw new Error(`Too many attempts. Wait ${wait} min.`);
            }
            this.settings.failedAttempts = 0;
            await this.saveData(this.settings);
        }
    }

    async _recordFailure() {
        this.settings.failedAttempts  = (this.settings.failedAttempts || 0) + 1;
        this.settings.lastAttemptTime = Date.now();
        await this.saveData(this.settings);
    }

    // ── Vault storage

    async _saveToVault(customKey = null) {
        const key = customKey || this._key;
        if (!key) return;

        const files = {};
        const folder = this.app.vault.getAbstractFileByPath(VAULT_FOLDER);
        if (folder && folder.children) {
            await this._walkFolder(folder.children, '', files);
        }

        const json      = JSON.stringify(files);
        const iv        = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv }, key, new TextEncoder().encode(json));

        const out = new Uint8Array(12 + encrypted.byteLength);
        out.set(iv);
        out.set(new Uint8Array(encrypted), 12);
        await this.app.vault.adapter.writeBinary(VAULT_FILE, out);
        await this.saveData(this.settings);
    }

    async _walkFolder(children, prefix, out) {
        const textExts  = new Set(['md','txt','json','css','js','html','xml','svg']);
        const supported = new Set(this.settings.supportedExts);
        for (const child of children) {
            const rel = prefix ? `${prefix}/${child.name}` : child.name;
            if (child.children) {
                await this._walkFolder(child.children, rel, out);
            } else {
                const ext = (child.extension || '').toLowerCase();
                if (!supported.has(ext)) continue;
                try {
                    if (textExts.has(ext)) {
                        out[rel] = await this.app.vault.read(child);
                    } else {
                        const buf = await this.app.vault.readBinary(child);
                        out[rel] = '__BIN__:' + this._toBase64(buf);
                    }
                } catch (e) { this._logError(e, `read:${rel}`); }
            }
        }
    }

    async _loadFromVault() {
        if (!(await this.app.vault.adapter.exists(VAULT_FILE))) return;

        const raw   = await this.app.vault.adapter.readBinary(VAULT_FILE);
        const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
        if (bytes.byteLength < 13) throw new Error('Vault file is corrupted.');

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: bytes.slice(0, 12) },
                                                      this._key,
                                                      bytes.slice(12));

        const files = JSON.parse(new TextDecoder().decode(decrypted));

        if (!(await this.app.vault.adapter.exists(VAULT_FOLDER))) {
            await this.app.vault.adapter.mkdir(VAULT_FOLDER);
        }

        for (const [rel, content] of Object.entries(files)) {
            const safe = rel.replace(/\.\./g, '').replace(/^\/+/, '');
            if (!safe) continue;
            await this._ensureDir(safe);
            const full = `${VAULT_FOLDER}/${safe}`;
            if (typeof content === 'string' && content.startsWith('__BIN__:')) {
                const bin = Uint8Array.from(atob(content.slice(8)), c => c.charCodeAt(0));
                await this.app.vault.adapter.writeBinary(full, bin);
            } else {
                await this.app.vault.adapter.write(full, content);
            }
        }
    }

    async _ensureDir(relPath) {
        const parts = relPath.split('/');
        let cur = VAULT_FOLDER;
        for (let i = 0; i < parts.length - 1; i++) {
            cur += '/' + parts[i];
            if (!(await this.app.vault.adapter.exists(cur)))
                await this.app.vault.adapter.mkdir(cur);
        }
    }

    async _cleanupFolder() {
        if (await this.app.vault.adapter.exists(VAULT_FOLDER)) {
            try { await this.app.vault.adapter.rmdir(VAULT_FOLDER, true); } catch (_) {}
        }
    }

    _toBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let s = '';
        for (let i = 0; i < bytes.length; i += 8192)
            s += String.fromCharCode(...bytes.subarray(i, i + 8192));
        return btoa(s);
    }

    // ── Lock / unlock

    async _unlock(pin) {
        this._key       = await this._deriveKey(pin);
        await this._loadFromVault();
        this.isUnlocked = true;
        this._bumpActivity();
        this._updateRibbon();
        new Notice('🔓 Safe Vault unlocked');
        this.app.workspace.trigger('layout-change');
    }

    async _lockVault() {
        if (!this.isUnlocked) return;
        try {
            await this._saveToVault();
        } catch (e) {
            this._logError(e, 'lock:save');
            new Notice('⚠️ Save failed — vault NOT locked to prevent data loss.');
            return;
        }
        this.isUnlocked = false;
        this._key       = null;
        this._updateRibbon();
        await this._cleanupFolder();
        new Notice('🔐 Safe Vault locked');
    }

    _updateRibbon() {
        if (!this.ribbonEl) return;
        this.ribbonEl.ariaLabel = this.isUnlocked ? 'Safe Vault (click to lock)' : 'Safe Vault (click to unlock)';
        this.ribbonEl.setAttribute('aria-label', this.ribbonEl.ariaLabel);
    }

    // ── Auto-lock

    _bumpActivity() { this._lastActivity = Date.now(); }

    _startAutoLockTimer() {
        if (this._autoTimer) clearInterval(this._autoTimer);
        this._autoTimer = setInterval(() => {
            if (!this.isUnlocked) return;
            const idle = (Date.now() - this._lastActivity) / 60000;
            if (idle >= this.settings.autoLockMinutes) this._lockVault();
        }, 30_000);
    }

    // ── PIN validation

    validatePin(pin) {
        const min = this.settings.minPinLength || 6;
        if (pin.length < min)                                       return `PIN must be at least ${min} characters.`;
        if (pin.length > 30)                                        return 'PIN must be 30 characters or less.';
        if (this.settings.requireNumbers  && !/\d/.test(pin))      return 'PIN must contain at least one digit.';
        if (this.settings.requireLetters  && !/[a-zA-Z]/.test(pin))return 'PIN must contain at least one letter.';
        if (/(.)\1{2,}/.test(pin))                                  return 'PIN must not have 3+ repeated characters.';
        return null;
    }

    // ── Recovery codes

    generateRecoveryCodes() {
        return Array.from({ length: 6 }, () => {
            const b = crypto.getRandomValues(new Uint8Array(6));
            return Array.from(b).map(x => x.toString(36).toUpperCase().padStart(2,'0')).join('').slice(0, 8);
        });
    }

    // ── Modals (entry points)

    _showLockModal() {
        new LockModal(this.app, this).open();
    }

    // ── Export / import

    async exportVaultBin() {
        if (!(await this.app.vault.adapter.exists(VAULT_FILE))) {
            new Notice('No vault file found.'); return;
        }
        const data = await this.app.vault.adapter.readBinary(VAULT_FILE);
        this._download(new Blob([data], { type: 'application/octet-stream' }),
                       `safe-vault-${Date.now()}.bin`);
        new Notice('✅ Vault exported');
    }

    async importVaultBin(file) {
        const buf = await file.arrayBuffer();
        await this.app.vault.adapter.writeBinary(VAULT_FILE, new Uint8Array(buf));
        new Notice('✅ Vault imported. Please unlock to verify.');
    }

    async exportSettings() {
        const data = { version: 1, settings: { ...this.settings } };
        this._download(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
                       `safe-vault-settings-${Date.now()}.json`);
        new Notice('✅ Settings exported');
    }

    async importSettings(file) {
        try {
            const text = await file.text();
            const data = JSON.parse(text);
            if (data.version === 1 && data.settings) {
                Object.assign(this.settings, data.settings);
                await this.saveData(this.settings);
                new Notice('✅ Settings imported. Please restart Obsidian.');
                return true;
            }
            new Notice('❌ Invalid settings file.');
        } catch (e) {
            this._logError(e, 'importSettings');
            new Notice('❌ Import failed.');
        }
        return false;
    }

    _download(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ── Error logging ──────────────────────────

    _logError(err, ctx = '') {
        if (!Array.isArray(this.settings.errors)) this.settings.errors = [];
        this.settings.errors.unshift({ message: String(err.message || err), ctx, time: Date.now() });
        if (this.settings.errors.length > 30) this.settings.errors.length = 30;
        this.saveData(this.settings);
    }
};


//  MODALS

// ── Lock screen

class LockModal extends Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
        this.modalEl.addClass('safe-vault-modal');
    }

    onOpen() {
        const { contentEl, plugin } = this;
        const isSetup = !plugin.settings.pinHash;
        let localFails = 0;

        contentEl.createEl('h2', { text: isSetup ? '🛡️ Set up Safe Vault' : '🔐 Unlock Safe Vault' });
        contentEl.createEl('p', {
            text: isSetup ? 'Create a PIN to protect your vault.' : 'Enter your PIN to access the vault.',
            cls: 'safe-vault-subtitle'
        });

        const pinInput = contentEl.createEl('input', {
            type: 'password',
            placeholder: isSetup ? 'Create PIN…' : 'Enter PIN…',
            cls: 'safe-vault-pin-input',
        });
        pinInput.autocomplete = 'off';
        pinInput.inputMode = 'text';

        let confirmInput = null;
        if (isSetup) {
            confirmInput = contentEl.createEl('input', {
                type: 'password',
                placeholder: 'Confirm PIN…',
                cls: 'safe-vault-pin-input',
            });
            confirmInput.autocomplete = 'off';
        }

        const errorEl = contentEl.createEl('p', { cls: 'safe-vault-error', text: '' });

        const btnRow = contentEl.createDiv({ cls: 'safe-vault-btn-row' });

        const submitBtn = btnRow.createEl('button', {
            text: isSetup ? 'Create vault' : 'Unlock',
            cls: 'mod-cta',
        });

        if (!isSetup) {
            const forgotBtn = btnRow.createEl('button', { text: 'Forgot PIN?', cls: 'safe-vault-forgot' });
            forgotBtn.addEventListener('click', () => {
                this.close();
                new RecoveryModal(this.app, plugin).open();
            });
        }

        const handleSubmit = async () => {
            const pin = pinInput.value.trim();
            if (!pin) return;

            try {
                await plugin._checkBruteForce();
            } catch (e) {
                errorEl.setText(e.message);
                return;
            }

            if (isSetup) {
                // --- First-time setup ---
                const err = plugin.validatePin(pin);
                if (err) { errorEl.setText(err); return; }
                if (confirmInput && pin !== confirmInput.value) {
                    errorEl.setText('PINs do not match.'); return;
                }
                plugin.settings.pinHash = await plugin._hashPin(pin);
                plugin._key             = await plugin._deriveKey(pin);
                const codes             = plugin.generateRecoveryCodes();
                plugin.settings.recoveryCodes = codes;
                await plugin.saveData(plugin.settings);
                this.close();
                new RecoveryCodesModal(this.app, plugin, codes).open();
                await plugin._unlock(pin);
            } else {
                // --- Normal unlock ---
                const ok = await plugin._verifyPin(pin);
                if (ok) {
                    plugin.settings.failedAttempts = 0;
                    await plugin.saveData(plugin.settings);
                    this.close();
                    await plugin._unlock(pin);
                } else {
                    await plugin._recordFailure();
                    localFails++;
                    pinInput.value = '';
                    const rem = Math.max(0, 5 - plugin.settings.failedAttempts);
                    errorEl.setText(rem > 0
                    ? `❌ Wrong PIN. Attempts left: ${rem}`
                    : '⛔ Locked for 5 minutes.');
                    if (localFails >= 3) errorEl.setText(errorEl.getText() + ' Forgot PIN?');
                }
            }
        };

        submitBtn.addEventListener('click', handleSubmit);
        pinInput.addEventListener('keydown', e => { if (e.key === 'Enter') handleSubmit(); });
        if (confirmInput) confirmInput.addEventListener('keydown', e => { if (e.key === 'Enter') handleSubmit(); });

        setTimeout(() => pinInput.focus(), 50);
        this._injectStyles();
    }

    onClose() { this.contentEl.empty(); }

    _injectStyles() {
        if (document.getElementById('safe-vault-styles')) return;
        const s = document.createElement('style');
        s.id = 'safe-vault-styles';
        s.textContent = `
        .safe-vault-modal { max-width: 380px; }
        .safe-vault-subtitle { color: var(--text-muted); margin-bottom: 16px; }
        .safe-vault-pin-input {
            width: 100%; padding: 10px 14px; font-size: 18px;
            letter-spacing: 4px; border-radius: 6px; margin-bottom: 10px;
            border: 1px solid var(--background-modifier-border);
            background: var(--background-primary-alt);
            color: var(--text-normal);
        }
        .safe-vault-error { color: var(--text-error); min-height: 20px; margin: 6px 0 10px; font-size: 13px; }
        .safe-vault-btn-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 8px; }
        .safe-vault-forgot { background: none; border: none; color: var(--text-muted);
            cursor: pointer; font-size: 13px; padding: 0; text-decoration: underline; }
            `;
            document.head.appendChild(s);
    }
}


// ── Recovery

class RecoveryModal extends Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
    }

    onOpen() {
        const { contentEl, plugin } = this;
        contentEl.createEl('h2', { text: '🔓 Recover access' });

        new Setting(contentEl)
        .setName('Recovery code')
        .setDesc('Enter one of your saved recovery codes.')
        .addText(t => {
            t.setPlaceholder('XXXXXXXX');
            t.inputEl.style.textTransform = 'uppercase';
            this._code = '';
            t.onChange(v => this._code = v.toUpperCase().trim());
        })
        .addButton(b => b.setButtonText('Use code').setCta().onClick(async () => {
            const codes = plugin.settings.recoveryCodes || [];
            const idx   = codes.indexOf(this._code);
            if (idx === -1) { new Notice('❌ Invalid code.'); return; }
            codes.splice(idx, 1);
            plugin.settings.recoveryCodes = codes;
            await plugin.saveData(plugin.settings);
            new Notice('✅ Code accepted. Set a new PIN.');
            this.close();
            new ChangePinModal(this.app, plugin, true).open();
        }));

        contentEl.createEl('p', {
            text: '💡 Recovery codes were shown when you first created your PIN. Each code can only be used once.',
            cls: 'setting-item-description',
            attr: { style: 'margin-top: 16px;' }
        });
    }

    onClose() { this.contentEl.empty(); }
}


// ── Change PIN

class ChangePinModal extends Modal {
    constructor(app, plugin, skipOld = false) {
        super(app);
        this.plugin  = plugin;
        this.skipOld = skipOld;
    }

    onOpen() {
        const { contentEl, plugin } = this;
        contentEl.createEl('h2', { text: '🔑 Change PIN' });

        let oldPin = '', newPin = '', confirmPin = '';
        const errEl = contentEl.createEl('p', { cls: 'safe-vault-error', text: '' });

        if (!this.skipOld) {
            new Setting(contentEl).setName('Current PIN').addText(t => {
                t.inputEl.type = 'password';
                t.onChange(v => oldPin = v);
            });
        }
        new Setting(contentEl).setName('New PIN').addText(t => {
            t.inputEl.type = 'password';
            t.onChange(v => newPin = v);
        });
        new Setting(contentEl).setName('Confirm new PIN').addText(t => {
            t.inputEl.type = 'password';
            t.onChange(v => confirmPin = v);
        });

        new Setting(contentEl).addButton(b => b.setButtonText('Update PIN').setCta().onClick(async () => {
            if (!this.skipOld) {
                const ok = await plugin._verifyPin(oldPin);
                if (!ok) { errEl.setText('❌ Current PIN is wrong.'); return; }
            }
            const err = plugin.validatePin(newPin);
            if (err) { errEl.setText(err); return; }
            if (newPin !== confirmPin) { errEl.setText('❌ PINs do not match.'); return; }

            const newKey  = await plugin._deriveKey(newPin);
            if (plugin.isUnlocked) await plugin._saveToVault(newKey);

            plugin.settings.pinHash       = await plugin._hashPin(newPin);
            plugin._key                   = newKey;
            plugin.settings.failedAttempts = 0;
            const codes = plugin.generateRecoveryCodes();
            plugin.settings.recoveryCodes  = codes;
            await plugin.saveData(plugin.settings);
            new Notice('✅ PIN updated!');
            this.close();
            new RecoveryCodesModal(this.app, plugin, codes).open();
        }));
    }

    onClose() { this.contentEl.empty(); }
}


// ── Recovery codes display

class RecoveryCodesModal extends Modal {
    constructor(app, plugin, codes) {
        super(app);
        this.plugin = plugin;
        this.codes  = codes;
    }

    onOpen() {
        const { contentEl, codes, plugin } = this;
        contentEl.createEl('h2', { text: '🔑 Recovery codes' });
        contentEl.createEl('p', {
            text: '⚠️ Save these codes somewhere safe. Each can only be used once.',
            attr: { style: 'color: var(--text-warning); margin-bottom: 12px;' }
        });

        const grid = contentEl.createDiv({ attr: { style: 'display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px;' } });
        codes.forEach(code => {
            grid.createEl('code', {
                text: code,
                attr: { style: 'background:var(--background-secondary);padding:6px 10px;border-radius:4px;text-align:center;font-size:14px;' }
            });
        });

        new Setting(contentEl)
        .setName('Download recovery file')
        .setDesc('Keep this JSON alongside your backup.')
        .addButton(b => b.setButtonText('Download').setCta().onClick(async () => {
            const data = { version: 1, timestamp: Date.now(), pinHash: plugin.settings.pinHash,
                salt: plugin.settings.salt, pinSalt: plugin.settings.pinSalt };
                plugin._download(
                    new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
                                 `safe-vault-recovery-${Date.now()}.json`);
                new Notice('✅ Recovery file saved.');
        }));

        new Setting(contentEl).addButton(b => b.setButtonText('I have saved the codes').onClick(() => this.close()));
    }

    onClose() { this.contentEl.empty(); }
}


//  SETTINGS TAB

class SafeVaultSettingTab extends PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin  = plugin;
        this._tab    = 'status';
    }

    display() {
        const { containerEl, plugin } = this;
        containerEl.empty();
        containerEl.addClass('safe-vault-settings');

        // Tab bar
        const tabBar  = containerEl.createDiv({ cls: 'safe-vault-tab-bar' });
        const TABS    = [
            { id: 'status',   label: '📊 Status'   },
            { id: 'security', label: '🔒 Security'  },
            { id: 'files',    label: '📎 Files'     },
            { id: 'backup',   label: '💾 Backup'    },
            { id: 'errors',   label: '🪵 Log'       },
        ];
        TABS.forEach(t => {
            const el = tabBar.createEl('button', { text: t.label, cls: 'safe-vault-tab-btn' });
            if (this._tab === t.id) el.addClass('active');
            el.addEventListener('click', () => { this._tab = t.id; this.display(); });
        });

        containerEl.createEl('div', { cls: 'safe-vault-tab-body', attr: { style: 'padding-top:16px;' } });

        switch (this._tab) {
            case 'status':   this._tabStatus();   break;
            case 'security': this._tabSecurity(); break;
            case 'files':    this._tabFiles();    break;
            case 'backup':   this._tabBackup();   break;
            case 'errors':   this._tabErrors();   break;
        }

        this._injectSettingsStyles();
    }

    // ── Status

    _tabStatus() {
        const { containerEl, plugin } = this;
        const s = plugin.settings;

        containerEl.createEl('h3', { text: '📊 Vault status' });

        const card = containerEl.createDiv({ cls: 'sv-card' });
        const rows = [
            ['State',         plugin.isUnlocked ? '🟢 Unlocked' : '🔴 Locked'],
            ['PIN set',       s.pinHash ? '✅ Yes' : '❌ No'],
            ['Brute-force',   `${s.failedAttempts || 0}/5 attempts`],
            ['Auto-lock',     `After ${s.autoLockMinutes} min idle`],
            ['Recovery codes',`${(s.recoveryCodes || []).length} remaining`],
        ];
        rows.forEach(([k, v]) => {
            const r = card.createDiv({ cls: 'sv-row' });
            r.createSpan({ text: k, attr: { style: 'color:var(--text-muted);' } });
            r.createSpan({ text: v });
        });

        containerEl.createEl('h3', { text: '⚙️ Actions', attr: { style: 'margin-top:20px;' } });

        new Setting(containerEl).setName('Change PIN')
        .addButton(b => b.setButtonText('Change').setCta()
        .onClick(() => new ChangePinModal(this.app, plugin).open()));

        new Setting(containerEl).setName('Reset failed attempts counter')
        .setDesc(`Currently: ${s.failedAttempts || 0}`)
        .addButton(b => b.setButtonText('Reset').setWarning().onClick(async () => {
            plugin.settings.failedAttempts = 0;
            plugin.settings.lastAttemptTime = 0;
            await plugin.saveData(plugin.settings);
            new Notice('✅ Counter reset.');
            this.display();
        }));

        if ((s.recoveryCodes || []).length > 0) {
            new Setting(containerEl).setName('View recovery codes')
            .addButton(b => b.setButtonText('Show')
            .onClick(() => new RecoveryCodesModal(this.app, plugin, s.recoveryCodes).open()));
        }
    }

    // ── Security

    _tabSecurity() {
        const { containerEl, plugin } = this;
        const s = plugin.settings;
        containerEl.createEl('h3', { text: '🔒 Security settings' });

        new Setting(containerEl)
        .setName('Auto-lock after idle (minutes)')
        .setDesc('Vault locks automatically when you stop interacting.')
        .addSlider(sl => sl.setLimits(1, 60, 1).setValue(s.autoLockMinutes).setDynamicTooltip()
        .onChange(async v => {
            plugin.settings.autoLockMinutes = v;
            await plugin.saveData(plugin.settings);
            plugin._startAutoLockTimer();
        }));

        new Setting(containerEl)
        .setName('Minimum PIN length')
        .addSlider(sl => sl.setLimits(4, 20, 1).setValue(s.minPinLength || 6).setDynamicTooltip()
        .onChange(async v => {
            plugin.settings.minPinLength = v;
            await plugin.saveData(plugin.settings);
        }));

        new Setting(containerEl)
        .setName('Require at least one letter in PIN')
        .addToggle(t => t.setValue(s.requireLetters !== false)
        .onChange(async v => { plugin.settings.requireLetters = v; await plugin.saveData(plugin.settings); }));

        new Setting(containerEl)
        .setName('Require at least one digit in PIN')
        .addToggle(t => t.setValue(s.requireNumbers !== false)
        .onChange(async v => { plugin.settings.requireNumbers = v; await plugin.saveData(plugin.settings); }));
    }

    // ── Files

    _tabFiles() {
        const { containerEl, plugin } = this;
        const s = plugin.settings;
        containerEl.createEl('h3', { text: '📎 Supported file types' });
        containerEl.createEl('p', {
            text: 'Only files with these extensions will be encrypted and stored in the vault.',
            cls: 'setting-item-description'
        });

        const ALL_EXTS = ['md','txt','json','css','js','html','xml','svg',
        'png','jpg','jpeg','gif','webp','pdf',
        'doc','docx','xls','xlsx','zip','7z','rar'];

        ALL_EXTS.forEach(ext => {
            new Setting(containerEl).setName(`.${ext}`)
            .addToggle(t => t.setValue((s.supportedExts || []).includes(ext))
            .onChange(async v => {
                const cur = new Set(plugin.settings.supportedExts || []);
                v ? cur.add(ext) : cur.delete(ext);
                plugin.settings.supportedExts = Array.from(cur);
                await plugin.saveData(plugin.settings);
            }));
        });
    }

    // ── Backup

    _tabBackup() {
        const { containerEl, plugin } = this;
        containerEl.createEl('h3', { text: '💾 Backup & restore' });

        new Setting(containerEl).setName('Export encrypted vault (.bin)')
        .setDesc('Download the encrypted vault file as a backup.')
        .addButton(b => b.setButtonText('Export').setCta()
        .onClick(() => plugin.exportVaultBin()));

        new Setting(containerEl).setName('Import encrypted vault (.bin)')
        .setDesc('Restore vault from a backup file.')
        .addButton(b => b.setButtonText('Choose file').onClick(() => {
            const inp = Object.assign(document.createElement('input'), { type: 'file', accept: '.bin' });
            inp.onchange = (e) => { const f = e.target.files[0]; if (f) plugin.importVaultBin(f); };
            inp.click();
        }));

        containerEl.createEl('hr');

        new Setting(containerEl).setName('Export settings (.json)')
        .addButton(b => b.setButtonText('Export').setCta()
        .onClick(() => plugin.exportSettings()));

        new Setting(containerEl).setName('Import settings (.json)')
        .addButton(b => b.setButtonText('Choose file').onClick(() => {
            const inp = Object.assign(document.createElement('input'), { type: 'file', accept: '.json' });
            inp.onchange = (e) => { const f = e.target.files[0]; if (f) plugin.importSettings(f); };
            inp.click();
        }));

        containerEl.createEl('p', {
            text: '💡 Tip: back up both the .bin vault file and the settings/salts JSON. Without the salts JSON you cannot decrypt a vault backup.',
            cls: 'setting-item-description',
            attr: { style: 'margin-top:16px;' }
        });
    }

    // ── Error log

    _tabErrors() {
        const { containerEl, plugin } = this;
        const errors = plugin.settings.errors || [];
        containerEl.createEl('h3', { text: '🪵 Error log' });

        if (errors.length === 0) {
            containerEl.createEl('p', { text: 'No errors recorded.', cls: 'setting-item-description' });
        } else {
            errors.forEach(e => {
                const card = containerEl.createDiv({ cls: 'sv-card', attr: { style: 'margin-bottom:10px;' } });
                const ago  = Math.round((Date.now() - e.time) / 60000);
                card.createEl('div', { text: `${ago} min ago — ${e.ctx || ''}`, attr: { style: 'color:var(--text-muted);font-size:12px;margin-bottom:4px;' } });
                card.createEl('div', { text: e.message, attr: { style: 'color:var(--text-error);' } });
            });
        }

        new Setting(containerEl).setName('Clear error log')
        .addButton(b => b.setButtonText('Clear').setWarning().onClick(async () => {
            plugin.settings.errors = [];
            await plugin.saveData(plugin.settings);
            new Notice('✅ Log cleared.');
            this.display();
        }));
    }

    // ── Settings styles

    _injectSettingsStyles() {
        if (document.getElementById('safe-vault-settings-styles')) return;
        const s = document.createElement('style');
        s.id = 'safe-vault-settings-styles';
        s.textContent = `
        .safe-vault-tab-bar {
            display: flex; gap: 4px; flex-wrap: wrap;
            border-bottom: 1px solid var(--background-modifier-border);
            padding-bottom: 4px; margin-bottom: 16px;
        }
        .safe-vault-tab-btn {
            background: none; border: none; cursor: pointer;
            padding: 6px 12px; border-radius: 6px 6px 0 0;
            color: var(--text-muted); font-size: 13px;
        }
        .safe-vault-tab-btn.active {
            color: var(--interactive-accent);
            border-bottom: 2px solid var(--interactive-accent);
            font-weight: 600;
        }
        .sv-card {
            background: var(--background-secondary);
            border-radius: 8px; padding: 12px 16px; margin-bottom: 16px;
        }
        .sv-row {
            display: flex; justify-content: space-between;
            padding: 5px 0; border-bottom: 1px solid var(--background-modifier-border);
            font-size: 13px;
        }
        .sv-row:last-child { border-bottom: none; }
        `;
        document.head.appendChild(s);
    }
}
