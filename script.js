const translations = {
    ua: {
        login_title: "Вхід у систему",
        username_label: "Ім'я користувача",
        password_label: "Пароль",
        btn_login: "Увійти",
        user_prefix: "Користувач:",
        btn_logout: "Вихід",
        tab_encrypt: "Шифрування",
        tab_decrypt: "Вхідні файли",
        encrypt_header: "Шифрування повідомлення",
        key_label: "Секретний ключ",
        message_label: "Текст повідомлення",
        btn_encrypt_action: "Зашифрувати",
        enc_result_label: "Результат (Nonce + Шифротекст + Tag):",
        send_header: "Дії з файлом",
        btn_send: "Зберегти на сервер",
        btn_download: "Скачати файл",
        decrypt_header: "Розшифрування файлів",
        server_files_header: "Файли на сервері:",
        no_files: "Немає нових повідомлень",
        decrypt_input_label: "Вміст зашифрованого файлу",
        key_label_dec: "Секретний ключ",
        btn_decrypt_action: "Розшифрувати та перевірити",
        dec_result_label: "Розшифрований текст:",
        btn_upload_file: "Відкрити файл з ПК",

        ph_username: "user_01",
        ph_password: "••••••••",
        ph_key: "Введіть ключ...",
        ph_text: "Введіть текст...",
        ph_cipher: "Вставте шифр сюди...",
        ph_filename: "file.txt",
        
        file_loaded: "Файл успішно завантажено!", 
        
        msg_saved: "Файл збережено!",
        msg_deleted: "Файл видалено!",
        msg_copied: "Скопійовано в буфер!",
        msg_key_gen: "Новий ключ згенеровано!",
        status_ok: "Цілісність підтверджено (Poly1305)",
        status_fail: "ПОМИЛКА! Дані пошкоджено!",
        error_login: "Невірний логін або пароль!",
        error_empty: "Заповніть усі поля!",
        file_from: "Від:",
        file_date: "Дата:"

        
    },
    en: {
        login_title: "System Login",
        username_label: "Username",
        password_label: "Password",
        btn_login: "Sign In",
        user_prefix: "User:",
        btn_logout: "Logout",
        tab_encrypt: "Encryption",
        tab_decrypt: "Incoming Files",
        encrypt_header: "Message Encryption",
        key_label: "Secret Key",
        message_label: "Message Text",
        btn_encrypt_action: "Encrypt",
        enc_result_label: "Result (Nonce + Ciphertext + Tag):",
        send_header: "File Actions",
        btn_send: "Save to Server",
        btn_download: "Download File",
        decrypt_header: "File Decryption",
        server_files_header: "Server Files:",
        no_files: "No new messages",
        decrypt_input_label: "Encrypted File Content",
        key_label_dec: "Secret Key",
        btn_decrypt_action: "Decrypt & Verify",
        dec_result_label: "Decrypted Text:",
        btn_upload_file: "Open Local File",

        ph_username: "user_01",
        ph_password: "••••••••",
        ph_key: "Enter key...",
        ph_text: "Enter message...",
        ph_cipher: "Paste ciphertext here...",
        ph_filename: "file.txt",
        
        file_loaded: "File loaded successfully!",
        
        msg_saved: "File saved!",
        msg_deleted: "File deleted!",
        msg_copied: "Copied!",
        msg_key_gen: "New key generated!",
        status_ok: "Integrity Verified (Poly1305)",
        status_fail: "ERROR! Data corrupted!",
        error_login: "Invalid credentials!",
        error_empty: "Please fill in all fields!",
        file_from: "From:",
        file_date: "Date:"
    }
};

let currentLang = 'ua';
let currentUser = null;
let currentUserInfo = null;
let sessionTimeout;

function setLanguage(lang) {
    currentLang = lang;

    document.querySelectorAll('[data-lang]').forEach(el => {
        const key = el.getAttribute('data-lang');
        if (translations[lang][key]) {
            const icon = el.querySelector('i');
            el.innerText = translations[lang][key];
            if (icon) el.prepend(icon, " ");
        }
    });

    document.querySelectorAll('[data-text]').forEach(el => {
        const key = el.getAttribute('data-text');
        if (translations[lang][key]) el.innerText = translations[lang][key];
    });

    document.querySelectorAll('[data-ph]').forEach(el => {
        const key = el.getAttribute('data-ph');
        if (translations[lang][key]) {
            el.placeholder = translations[lang][key];
        }
    });

    document.querySelectorAll('.lang-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`.lang-btn[onclick="setLanguage('${lang}')"]`).classList.add('active');
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const iconClass = type === 'success' ? 'fa-circle-check' : 'fa-triangle-exclamation';
    toast.innerHTML = `<i class="fa-solid ${iconClass}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 3000);
}

function togglePass(id, btn) {
    const input = document.getElementById(id);
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

function generateKey(id) {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let password = "";
    for (let i = 0; i < 16; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    document.getElementById(id).value = password;
    showToast(translations[currentLang].msg_key_gen);
}

function copyResult(id) {
    const text = document.getElementById(id);
    text.select();
    document.execCommand('copy');
    showToast(translations[currentLang].msg_copied);
}

function resetTimer() {
    clearTimeout(sessionTimeout);
    if(currentUser) {
        sessionTimeout = setTimeout(() => {
            alert("Session expired due to inactivity.");
            location.reload();
        }, 5 * 60 * 1000); 
    }
}
document.onmousemove = resetTimer;
document.onkeypress = resetTimer;

const USERS_DB = {
    'ceo': { pass: 'G@nDirector$Top', role: 'Генеральний директор', dept: 'admin' },
    'secretary': { pass: 'Office#Gate', role: 'Секретар', dept: 'admin' },
    'lawyer': { pass: 'L@wyer2025!', role: 'Юрист', dept: 'legal' },
    'chief_accountant': { pass: 'M@inAcc#99', role: 'Головний бухгалтер', dept: 'finance' },
    'economist': { pass: 'Eco#Graph25', role: 'Економіст', dept: 'finance' },
    'head_hr': { pass: 'HR_Boss!', role: 'Керівник відділу кадрів', dept: 'hr' },
    'head_sales': { pass: 'S@lesLead', role: 'Керівник відділу продажу', dept: 'sales' },
    'cto': { pass: 'TechDir#Root', role: 'Технічний директор', dept: 'dev' },
    'head_cybersec': { pass: 'SecurGuard!H', role: 'Керівник від. кібербезпеки', dept: 'security' },
    'head_security': { pass: 'Safe#Zone', role: 'Керівник від. охорони', dept: 'guard' }
};

function addUsersRange(prefix, count, passTemplate, roleName, deptCode) {
    for (let i = 1; i <= count; i++) {
        const num = i.toString().padStart(2, '0');
        const login = `${prefix}_${num}`;
        let password = passTemplate.includes('...') ? passTemplate.replace('...', num) : passTemplate.replace('01', num);
        USERS_DB[login] = { pass: password, role: roleName, dept: deptCode };
    }
}

addUsersRange('accountant', 4, 'Acc$User_...', 'Бухгалтер', 'finance');
addUsersRange('hr_manager', 4, 'HumanR_...', 'HR Менеджер', 'hr');
addUsersRange('sales_manager', 4, 'Sell$Buy_...', 'Менеджер продажу', 'sales');
addUsersRange('developer', 6, 'DevCode_...!', 'Розробник', 'dev');
addUsersRange('tester', 2, 'BugHunt@...', 'Тестувальник', 'qa');
addUsersRange('designer', 2, 'ArtPix#...', 'Дизайнер', 'design');
addUsersRange('it_specialist', 3, 'Admin..._Tool', 'IT Спеціаліст', 'it');
addUsersRange('cybersec', 4, 'Firewall_...', 'Кібербезпека', 'security');
addUsersRange('security', 3, 'GuardPost_...', 'Охоронець', 'guard');

function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
function quarterRound(x, a, b, c, d) {
    x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 16);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 12);
    x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 8);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 7);
}
function chachaBlock(key, nonce, counter) {
    const constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    const state = new Uint32Array(16);
    state.set(constants, 0); state.set(key, 4); state[12] = counter; state.set(nonce, 13);
    const workingState = new Uint32Array(state);
    for (let i = 0; i < 10; i++) {
        quarterRound(workingState, 0, 4, 8, 12); quarterRound(workingState, 1, 5, 9, 13);
        quarterRound(workingState, 2, 6, 10, 14); quarterRound(workingState, 3, 7, 11, 15);
        quarterRound(workingState, 0, 5, 10, 15); quarterRound(workingState, 1, 6, 11, 12);
        quarterRound(workingState, 2, 7, 8, 13); quarterRound(workingState, 3, 4, 9, 14);
    }
    for (let i = 0; i < 16; i++) workingState[i] = (workingState[i] + state[i]) >>> 0;
    return new Uint8Array(workingState.buffer);
}
function poly1305Mac(msg, key) {
    const r = (BigInt(key[0]) | (BigInt(key[1]) << 8n) | (BigInt(key[2]) << 16n) | (BigInt(key[3]) << 24n) | 
        (BigInt(key[4]) << 32n) | (BigInt(key[5]) << 40n) | (BigInt(key[6]) << 48n) | (BigInt(key[7]) << 56n) |
        (BigInt(key[8]) << 64n) | (BigInt(key[9]) << 72n) | (BigInt(key[10]) << 80n) | (BigInt(key[11]) << 88n) |
        (BigInt(key[12]) << 96n) | (BigInt(key[13]) << 104n) | (BigInt(key[14]) << 112n) | (BigInt(key[15]) << 120n)
    ) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const s = (BigInt(key[16]) | (BigInt(key[17]) << 8n) | (BigInt(key[18]) << 16n) | (BigInt(key[19]) << 24n) |
        (BigInt(key[20]) << 32n) | (BigInt(key[21]) << 40n) | (BigInt(key[22]) << 48n) | (BigInt(key[23]) << 56n) |
        (BigInt(key[24]) << 64n) | (BigInt(key[25]) << 72n) | (BigInt(key[26]) << 80n) | (BigInt(key[27]) << 88n) |
        (BigInt(key[28]) << 96n) | (BigInt(key[29]) << 104n) | (BigInt(key[30]) << 112n) | (BigInt(key[31]) << 120n));
    const p = (1n << 130n) - 5n;
    let acc = 0n;
    for (let i = 0; i < msg.length; i += 16) {
        let block = 0n;
        for (let j = 0; j < 16 && i + j < msg.length; j++) block |= BigInt(msg[i + j]) << (BigInt(j) * 8n);
        block |= 1n << (BigInt(Math.min(16, msg.length - i)) * 8n);
        acc = (acc + block) * r % p;
    }
    acc = (acc + s) % (1n << 128n);
    const tag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) tag[i] = Number((acc >> (BigInt(i) * 8n)) & 0xffn);
    return tag;
}

function stringToBytes(str) { return new TextEncoder().encode(str); }
function bytesToString(bytes) { return new TextDecoder().decode(bytes); }
function hexToBytes(hex) {
    const bytes = [];
    for (let c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
    return new Uint8Array(bytes);
}
function bytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }
async function deriveKey(password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveBits"]);
    const keyBytes = await window.crypto.subtle.deriveBits({name: "PBKDF2", salt: new Uint8Array(16), iterations: 1000, hash: "SHA-256"}, keyMaterial, 256);
    return new Uint32Array(keyBytes);
}

function clearAppFields() {
    document.getElementById('enc-text').value = '';
    document.getElementById('enc-key').value = '';
    document.getElementById('enc-output').value = '';
    document.getElementById('file-name').value = '';
    document.getElementById('enc-result-box').classList.add('hidden');
    document.getElementById('dec-input').value = '';
    document.getElementById('dec-key').value = '';
    document.getElementById('dec-output').value = '';
    document.getElementById('dec-result-box').classList.add('hidden');
    document.getElementById('dec-status').innerText = '';
}

document.getElementById('login-btn').addEventListener('click', () => {
    const user = document.getElementById('username').value.trim();
    const pass = document.getElementById('password').value.trim();
    if (USERS_DB[user] && USERS_DB[user].pass === pass) {
        currentUser = user;
        currentUserInfo = USERS_DB[user];
        document.getElementById('current-user').innerText = `${user} (${currentUserInfo.role})`;
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('app-screen').classList.remove('hidden');
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        clearAppFields();
        loadFiles();
        switchTab('encrypt-tab');
        resetTimer();
    } else {
        showToast(translations[currentLang].error_login, 'error');
    }
});

document.getElementById('logout-btn').addEventListener('click', () => location.reload());

window.switchTab = function(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.getElementById(tabId).classList.remove('hidden');
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}

document.getElementById('btn-encrypt').addEventListener('click', async () => {
    const text = document.getElementById('enc-text').value;
    const pass = document.getElementById('enc-key').value;
    if (!text || !pass) return showToast(translations[currentLang].error_empty, 'error');

    const key = await deriveKey(pass);
    const msgBytes = stringToBytes(text);
    const nonce = new Uint32Array(3); window.crypto.getRandomValues(nonce);
    const polyKey = chachaBlock(key, nonce, 0).slice(0, 32);
    
    let encBytes = new Uint8Array(msgBytes.length);
    for (let i = 0; i < msgBytes.length; i += 64) {
        const ks = chachaBlock(key, nonce, 1 + Math.floor(i / 64));
        for (let j = 0; j < 64 && i + j < msgBytes.length; j++) encBytes[i + j] = msgBytes[i + j] ^ ks[j];
    }
    
    const tag = poly1305Mac(encBytes, polyKey);
    const res = bytesToHex(new Uint8Array(nonce.buffer)) + ":" + bytesToHex(encBytes) + ":" + bytesToHex(tag);
    
    document.getElementById('enc-output').value = res;
    document.getElementById('enc-result-box').classList.remove('hidden');
});

document.getElementById('btn-send').addEventListener('click', () => {
    const content = document.getElementById('enc-output').value;
    const recipient = document.getElementById('recipient-select').value;
    const fname = document.getElementById('file-name').value || `msg_${Date.now()}.enc`;
    if (!content) return;

    let files = JSON.parse(localStorage.getItem('server_files') || "[]");
    files.push({ id: Date.now(), sender: currentUser, recipient: recipient, filename: fname, content: content, date: new Date().toLocaleString() });
    localStorage.setItem('server_files', JSON.stringify(files));
    
    showToast(translations[currentLang].msg_saved);
    clearAppFields();
    loadFiles();
});

document.getElementById('btn-download').addEventListener('click', () => {
    const content = document.getElementById('enc-output').value;
    const fname = document.getElementById('file-name').value || "encrypted.txt";
    if (!content) return;
    const el = document.createElement('a');
    el.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(content);
    el.download = fname;
    el.click();
});

function loadFiles() {
    const list = document.getElementById('file-list');
    list.innerHTML = "";
    let files = JSON.parse(localStorage.getItem('server_files') || "[]");
    
    const myFiles = files.filter(f => {
        if (f.recipient === 'all') return true;
        if (f.recipient === 'user_' + currentUser) return true;
        if (currentUserInfo && f.recipient === 'dept_' + currentUserInfo.dept) return true;
        if (f.sender === currentUser) return true;
        return false;
    });

    myFiles.forEach(f => {
        const isInc = f.sender !== currentUser;
        
        // Іконки
        let iconHtml = isInc 
            ? '<i class="fa-solid fa-envelope-open-text" style="color:var(--success)"></i>' 
            : '<i class="fa-solid fa-paper-plane" style="color:var(--text-muted)"></i>';

        const meta = isInc 
            ? `${translations[currentLang].file_from} ${f.sender}` 
            : `To: ${f.recipient}`;

        const li = document.createElement('li');
        li.className = "file-item";
        li.onclick = () => loadFileContent(f.content);
        li.innerHTML = `
            <div class="file-info">
                <span class="file-icon">${iconHtml}</span> 
                <strong>${f.filename}</strong> 
                <span class="file-meta">(${meta} | ${f.date})</span>
            </div>
            <div class="file-actions">
                <button class="btn-delete" onclick="event.stopPropagation(); deleteFile(${f.id})" title="Видалити">
                    <i class="fa-solid fa-trash-can"></i>
                </button>
            </div>
        `;
        list.appendChild(li);
    });
    if (myFiles.length === 0) list.innerHTML = `<li class="empty-msg">${translations[currentLang].no_files}</li>`;
}

window.deleteFile = function(id) {
    if(!confirm("Видалити?")) return;
    let files = JSON.parse(localStorage.getItem('server_files') || "[]");
    localStorage.setItem('server_files', JSON.stringify(files.filter(f => f.id !== id)));
    loadFiles();
    showToast(translations[currentLang].msg_deleted, 'error');
};

window.loadFileContent = function(content) {
    document.getElementById('dec-input').value = content;
    switchTab('decrypt-tab'); 
};

document.getElementById('file-upload').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;
    document.getElementById('file-name-display').innerText = file.name;
    const reader = new FileReader();
    reader.onload = function(ev) {
        document.getElementById('dec-input').value = ev.target.result;
        document.getElementById('dec-key').focus();
        showToast(translations[currentLang].file_loaded);
    };
    reader.readAsText(file);
    e.target.value = '';
});

document.getElementById('btn-decrypt').addEventListener('click', async () => {
    const input = document.getElementById('dec-input').value.trim();
    const pass = document.getElementById('dec-key').value;
    if (!input || !pass) return showToast(translations[currentLang].error_empty, 'error');

    try {
        const parts = input.split(':');
        if (parts.length !== 3) throw new Error();
        
        const nonce = new Uint32Array(hexToBytes(parts[0]).buffer);
        const encBytes = hexToBytes(parts[1]);
        const recvTag = hexToBytes(parts[2]);
        const key = await deriveKey(pass);
        
        const polyKey = chachaBlock(key, nonce, 0).slice(0, 32);
        const calcTag = poly1305Mac(encBytes, polyKey);
        
        let ok = true;
        for(let i=0; i<16; i++) if(recvTag[i] !== calcTag[i]) ok = false;

        const resBox = document.getElementById('dec-result-box');
        const status = document.getElementById('dec-status');
        const output = document.getElementById('dec-output');
        resBox.classList.remove('hidden');

        if (!ok) {
            status.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${translations[currentLang].status_fail}`;
            status.style.color = "var(--danger)";
            output.value = "ACCESS DENIED / DATA CORRUPTED";
            return;
        }

        status.innerHTML = `<i class="fa-solid fa-shield-check"></i> ${translations[currentLang].status_ok}`;
        status.style.color = "var(--success)";
        
        let decBytes = new Uint8Array(encBytes.length);
        for (let i = 0; i < encBytes.length; i += 64) {
            const ks = chachaBlock(key, nonce, 1 + Math.floor(i / 64));
            for (let j = 0; j < 64 && i + j < encBytes.length; j++) decBytes[i + j] = encBytes[i + j] ^ ks[j];
        }
        output.value = bytesToString(decBytes);

    } catch (e) {
        showToast("Помилка формату даних!", 'error');
    }
});

setLanguage('ua');