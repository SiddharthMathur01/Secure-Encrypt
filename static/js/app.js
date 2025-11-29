function showAlert(elementId, message, type = 'success') {
    const el = document.getElementById(elementId);
    el.className = `alert alert-${type} mt-3`;
    el.innerHTML = `<i class="bi bi-${type === 'success' ? 'check-circle' : 'exclamation-triangle'} me-2"></i> ${message}`;
    el.style.display = 'block';

    setTimeout(() => {
        el.style.display = 'none';
    }, 5000);
}

document.querySelectorAll('input[name="encrypt-mode"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        if (e.target.id === 'encrypt-text-mode') {
            document.getElementById('encrypt-text-section').style.display = 'block';
            document.getElementById('encrypt-file-section').style.display = 'none';
        } else {
            document.getElementById('encrypt-text-section').style.display = 'none';
            document.getElementById('encrypt-file-section').style.display = 'block';
        }
    });
});

document.querySelectorAll('input[name="decrypt-mode"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        if (e.target.id === 'decrypt-text-mode') {
            document.getElementById('decrypt-text-section').style.display = 'block';
            document.getElementById('decrypt-file-section').style.display = 'none';
        } else {
            document.getElementById('decrypt-text-section').style.display = 'none';
            document.getElementById('decrypt-file-section').style.display = 'block';
        }
    });
});

document.querySelectorAll('input[name="steg-mode"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        if (e.target.id === 'steg-hide-mode') {
            document.getElementById('steg-hide-section').style.display = 'block';
            document.getElementById('steg-reveal-section').style.display = 'none';
        } else {
            document.getElementById('steg-hide-section').style.display = 'none';
            document.getElementById('steg-reveal-section').style.display = 'block';
        }
    });
});

document.getElementById('show-advanced-encrypt').addEventListener('change', (e) => {
    document.getElementById('advanced-encrypt-options').style.display = e.target.checked ? 'block' : 'none';
});

document.getElementById('enable-expiry').addEventListener('change', (e) => {
    document.getElementById('expiry-options').style.display = e.target.checked ? 'block' : 'none';
});

const lengthSlider = document.getElementById('pass-gen-length');
const lengthDisplay = document.getElementById('pass-gen-length-display');

lengthSlider.addEventListener('input', (e) => {
    lengthDisplay.textContent = `${e.target.value} chars`;
});

document.getElementById('generate-passphrase-btn').addEventListener('click', () => {
    const length = parseInt(lengthSlider.value);
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
    let retVal = "";
    
    for (let i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }

    const display = document.getElementById('generated-passphrase-display');
    const text = document.getElementById('generated-passphrase-text');

    display.style.display = 'block';
    text.textContent = retVal;
    window.generatedPassphrase = retVal;
});

function useGeneratedPassphrase() {
    if (window.generatedPassphrase) {
        document.getElementById('encrypt-passphrase').value = window.generatedPassphrase;
        document.getElementById('encrypt-passphrase').dispatchEvent(new Event('input'));
        document.getElementById('generated-passphrase-display').style.display = 'none';
    }
}

document.getElementById('encrypt-passphrase').addEventListener('input', function () {
    const val = this.value;
    const result = zxcvbn(val);
    const bar = document.getElementById('encrypt-strength-bar');
    const text = document.getElementById('encrypt-strength-text');

    const colors = ['#ff4757', '#ff6b81', '#ffa502', '#2ed573', '#00ff9d'];
    const widths = ['20%', '40%', '60%', '80%', '100%'];
    const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];

    if (val.length === 0) {
        bar.style.width = '0%';
        text.textContent = 'Strength: Too short';
    } else {
        bar.style.width = widths[result.score];
        bar.style.backgroundColor = colors[result.score];
        text.textContent = `Strength: ${labels[result.score]}`;
    }
});

['encrypt', 'decrypt'].forEach(type => {
    document.getElementById(`toggle-${type}-pass`).addEventListener('click', function () {
        const input = document.getElementById(`${type}-passphrase`);
        const icon = this.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.classList.replace('bi-eye', 'bi-eye-slash');
        } else {
            input.type = 'password';
            icon.classList.replace('bi-eye-slash', 'bi-eye');
        }
    });
});

function setupDropZone(zoneId, inputId, previewId) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const preview = document.getElementById(previewId);

    zone.addEventListener('click', () => input.click());

    input.addEventListener('change', () => handleFiles(input.files));

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', () => {
        zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        input.files = e.dataTransfer.files;
        handleFiles(input.files);
    });

    function handleFiles(files) {
        if (files.length > 0) {
            let html = `<div class="d-flex flex-wrap gap-2">`;
            Array.from(files).forEach(file => {
                html += `
                    <div class="badge bg-secondary p-2 d-flex align-items-center">
                        <i class="bi bi-file-earmark me-2"></i>
                        ${file.name}
                        <span class="ms-2 opacity-50">(${(file.size / 1024 / 1024).toFixed(2)} MB)</span>
                    </div>`;
            });
            html += `</div>`;
            preview.innerHTML = html;
        }
    }
}

setupDropZone('encrypt-drop-zone', 'encrypt-file-input', 'encrypt-file-preview');
setupDropZone('decrypt-drop-zone', 'decrypt-file-input', 'decrypt-file-preview');

document.getElementById('encrypt-btn').addEventListener('click', async () => {
    const mode = document.querySelector('input[name="encrypt-mode"]:checked').id;
    const passphrase = document.getElementById('encrypt-passphrase').value;

    if (mode === 'encrypt-text-mode') {
        const plaintext = document.getElementById('plaintext').value;

        try {
            const res = await fetch('/encrypt/text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plaintext, passphrase })
            });
            const data = await res.json();

            if (data.success) {
                document.getElementById('plaintext').value = data.encrypted;
                showAlert('encrypt-alert', 'Text encrypted successfully! Content replaced above.');
            } else {
                showAlert('encrypt-alert', data.error, 'danger');
            }
        } catch (e) {
            showAlert('encrypt-alert', 'Network error occurred', 'danger');
        }
    } else {
        const fileInput = document.getElementById('encrypt-file-input');
        const useExpiry = document.getElementById('enable-expiry').checked;

        if (fileInput.files.length === 0) {
            showAlert('encrypt-alert', 'Please select a file', 'danger');
            return;
        }

        const formData = new FormData();
        formData.append('passphrase', passphrase);

        let endpoint = '/encrypt/file';

        if (fileInput.files.length > 1) {
            endpoint = '/encrypt/batch';
            Array.from(fileInput.files).forEach(f => formData.append('files', f));
        } else {
            if (useExpiry) {
                endpoint = '/encrypt/file_with_expiry';
                formData.append('expire_minutes', document.getElementById('expiry-time').value);
            }
            formData.append('file', fileInput.files[0]);
        }

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                
                const contentDisp = res.headers.get('Content-Disposition');
                let filename = 'encrypted_file';
                if (contentDisp && contentDisp.indexOf('filename=') !== -1) {
                    filename = contentDisp.split('filename=')[1].replace(/"/g, '');
                }
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                showAlert('encrypt-alert', 'File encrypted and downloaded!');
            } else {
                const data = await res.json();
                showAlert('encrypt-alert', data.error || 'Encryption failed', 'danger');
            }
        } catch (e) {
            showAlert('encrypt-alert', 'Network error', 'danger');
        }
    }
});

document.getElementById('decrypt-btn').addEventListener('click', async () => {
    const mode = document.querySelector('input[name="decrypt-mode"]:checked').id;
    const passphrase = document.getElementById('decrypt-passphrase').value;

    if (mode === 'decrypt-text-mode') {
        const encrypted = document.getElementById('encrypted-text').value;

        try {
            const res = await fetch('/decrypt/text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ encrypted, passphrase })
            });
            const data = await res.json();

            if (data.success) {
                document.getElementById('encrypted-text').value = data.plaintext;
                showAlert('decrypt-alert', 'Text decrypted successfully! Content revealed above.');
            } else {
                showAlert('decrypt-alert', data.error, 'danger');
            }
        } catch (e) {
            showAlert('decrypt-alert', 'Network error', 'danger');
        }
    } else {
        const fileInput = document.getElementById('decrypt-file-input');

        if (fileInput.files.length === 0) {
            showAlert('decrypt-alert', 'Please select a file', 'danger');
            return;
        }

        const formData = new FormData();
        formData.append('passphrase', passphrase);
        formData.append('file', fileInput.files[0]);

        let endpoint = '/decrypt/file';
        if (fileInput.files[0].name.includes('.expiring')) {
            endpoint = '/decrypt/file_with_expiry';
        }

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                
                const contentDisp = res.headers.get('Content-Disposition');
                let filename = 'decrypted_file';
                if (contentDisp && contentDisp.indexOf('filename=') !== -1) {
                    filename = contentDisp.split('filename=')[1].replace(/"/g, '');
                }
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                showAlert('decrypt-alert', 'File decrypted and downloaded!');
            } else {
                const data = await res.json();
                showAlert('decrypt-alert', data.error || 'Decryption failed', 'danger');
            }
        } catch (e) {
            showAlert('decrypt-alert', 'Network error', 'danger');
        }
    }
});

document.getElementById('steg-hide-btn').addEventListener('click', async () => {
    const image = document.getElementById('steg-cover-image').files[0];
    const file = document.getElementById('steg-secret-file').files[0];
    const passphrase = document.getElementById('steg-hide-passphrase').value;

    if (!image || !file || !passphrase) {
        showAlert('steg-alert', 'All fields are required', 'danger');
        return;
    }

    const formData = new FormData();
    formData.append('image', image);
    formData.append('file', file);
    formData.append('passphrase', passphrase);

    try {
        const res = await fetch('/steg/encrypt', {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'stego_image.png';
            document.body.appendChild(a);
            a.click();
            a.remove();
            showAlert('steg-alert', 'Data hidden in image successfully!');
        } else {
            const data = await res.json();
            showAlert('steg-alert', data.error, 'danger');
        }
    } catch (e) {
        showAlert('steg-alert', 'Network error', 'danger');
    }
});

document.getElementById('steg-reveal-btn').addEventListener('click', async () => {
    const image = document.getElementById('steg-image').files[0];
    const passphrase = document.getElementById('steg-reveal-passphrase').value;
    const filename = document.getElementById('steg-filename').value;

    if (!image || !passphrase) {
        showAlert('steg-alert', 'Image and passphrase are required', 'danger');
        return;
    }

    const formData = new FormData();
    formData.append('image', image);
    formData.append('passphrase', passphrase);
    if (filename) formData.append('filename', filename);

    try {
        const res = await fetch('/steg/decrypt', {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            
            const contentDisp = res.headers.get('Content-Disposition');
            let fname = 'revealed_file';
            if (contentDisp && contentDisp.indexOf('filename=') !== -1) {
                fname = contentDisp.split('filename=')[1].replace(/"/g, '');
            }
            a.download = fname;
            document.body.appendChild(a);
            a.click();
            a.remove();
            showAlert('steg-alert', 'Data revealed successfully!');
        } else {
            const data = await res.json();
            showAlert('steg-alert', data.error, 'danger');
        }
    } catch (e) {
        showAlert('steg-alert', 'Network error', 'danger');
    }
});

console.log('%c🔒 Secure-Encrypt', 'font-size: 20px; font-weight: bold; color: #00f2ff;');
console.log('%cAES-256-GCM Authenticated Encryption', 'font-size: 12px; color: #8f9bb3;');
console.log('%cAll encryption happens securely. No data is stored on the server.', 'font-size: 10px; color: #8f9bb3;');