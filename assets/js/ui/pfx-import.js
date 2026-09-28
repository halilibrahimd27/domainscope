/**
 * ui/pfx-import.js — opening a PKCS#12 (.pfx / .p12) file in the certificate loaders of the
 * Certificate view and SSL Targets step 1 (views/cert.js CertLoader), over lib/x509.js
 * loadCertificates() and lib/pkcs12.js.
 *
 * - {@link askPfxPassword}: the password dialog. The password lives in its field and in the one
 *   open call; a wrong one keeps the dialog open with the reason (the integrity check does not
 *   match, or — without one — nothing decrypts), and the field is emptied when the dialog closes.
 *   "Check that the private key matches the certificate" is off by default: only then is the key
 *   decrypted, in memory, for the check.
 * - {@link PfxNote}: what the bundle held and how it was protected, the key check's verdict and
 *   the actions a view adds (SSL Targets: Download fullchain.pem). The key itself is never shown.
 *
 * Every string is rendered through h() / text nodes.
 */

import { h } from './dom.js';
import { Alert, Badge, Icon, KeyValueList, Modal, checkbox, setButtonBusy, textInput } from './components.js';
import { t, registerStrings } from '../i18n.js';

registerStrings('en', {
  'pfx.title': 'Open the PKCS#12 file',
  'pfx.intro': '{name} is a PKCS#12 file (.pfx / .p12). Enter its password to read the certificates in it.',
  'pfx.password': 'Password',
  'pfx.passwordHint': 'Leave it empty if the file has no password.',
  'pfx.checkKey': 'Check that the private key matches the certificate',
  'pfx.checkKeyHint': 'The key is decrypted in this tab for the check only, then dropped. It is never shown or saved.',
  'pfx.privacy': 'The file and its password stay in this tab: nothing is uploaded and the password is not saved.',
  'pfx.open': 'Open',
  'pfx.wrong.mac': 'Wrong password: it does not match the file’s integrity check. If you are sure of the password, the file is damaged.',
  'pfx.wrong.noMac': 'Wrong password, or a damaged file: this file has no integrity check to tell the two apart.',
  'pfx.cancelled': '{name} was not opened.',

  'pfx.note.title': 'Read from a PKCS#12 file',
  'pfx.note.held': 'The file holds {certs} and {keys}.',
  'pfx.note.heldNoKey': 'The file holds {certs} and no private key.',
  'pfx.note.certs': { one: '{count} certificate', other: '{count} certificates' },
  'pfx.note.keys': { one: '{count} private key', other: '{count} private keys' },
  'pfx.note.keyHidden': 'Private keys are never shown or kept.',
  'pfx.note.friendlyName': 'Friendly name',
  'pfx.note.certsProtection': 'Certificates',
  'pfx.note.keyProtection': 'Private key',
  'pfx.note.integrity': 'Integrity check',
  'pfx.note.notEncrypted': 'not encrypted',
  'pfx.note.noMac': 'none',
  'pfx.note.iterations': { one: '{count} iteration', other: '{count} iterations' },
  'pfx.note.notSupported': 'not supported here',
  'pfx.note.unverified': 'This file has no integrity check and its certificates are not encrypted: they were read without the password, which was not checked.',
  'pfx.note.plainKey': {
    one: 'The private key is stored without encryption: anyone with the file has the key.',
    other: '{count} private keys are stored without encryption: anyone with the file has them.'
  },
  'pfx.strength.weak': 'weak',
  'pfx.strength.weakTitle': 'A 40- or 56-bit key that can be broken by trying every key. Harmless for certificates, which are public; a private key under it is not protected.',
  'pfx.strength.legacy': 'legacy',
  'pfx.strength.legacyTitle': 'Older algorithms (3DES, RC2, SHA-1) that current Windows and Java versions still read. Export with AES-256 when you can.',

  'pfx.key.match': 'The private key matches this certificate',
  'pfx.key.mismatch': 'The private key does not match this certificate',
  'pfx.key.mismatchBody': 'A server set up with this certificate and this key cannot complete a TLS handshake.',
  'pfx.key.owner': 'The key belongs to {name}.',
  'pfx.key.nokey': 'The file holds no private key: the server needs the key from elsewhere.',
  'pfx.key.unsupported': 'The browser cannot check this {algorithm} key.',
  'pfx.key.encryptionUnsupported': 'The key’s encryption ({what}) is not supported here, so the key cannot be checked.',
  'pfx.key.iterationsUnsupported': 'The key’s password is stretched with more iterations than this page runs, so the key cannot be checked.',
  'pfx.key.failed': 'The private key could not be decrypted with this password: it may have a password of its own, or the file is damaged.',
  'pfx.key.notChecked': 'The key was not checked. To check it, load the file again and tick “Check that the private key matches the certificate”.',

  'pfx.fullchain': 'Download fullchain.pem',
  'pfx.fullchainHint': 'The server certificate and its intermediates in the order servers send them, without the root and without the private key.'
});

registerStrings('tr', {
  'pfx.title': 'PKCS#12 dosyasını aç',
  'pfx.intro': '{name} bir PKCS#12 dosyası (.pfx / .p12). İçindeki sertifikaları okumak için parolasını girin.',
  'pfx.password': 'Parola',
  'pfx.passwordHint': 'Dosyanın parolası yoksa boş bırakın.',
  'pfx.checkKey': 'Özel anahtarın sertifikayla eşleştiğini denetle',
  'pfx.checkKeyHint': 'Anahtarın şifresi yalnızca denetim için bu sekmede çözülür; anahtar sonra atılır, hiçbir zaman gösterilmez ya da kaydedilmez.',
  'pfx.privacy': 'Dosya ve parolası bu sekmede kalır: hiçbir şey yüklenmez, parola kaydedilmez.',
  'pfx.open': 'Aç',
  'pfx.wrong.mac': 'Parola yanlış: dosyanın bütünlük denetimiyle eşleşmiyor. Paroladan eminseniz dosya bozuktur.',
  'pfx.wrong.noMac': 'Parola yanlış ya da dosya bozuk: bu dosyada ikisini ayırt edecek bir bütünlük denetimi yok.',
  'pfx.cancelled': '{name} açılmadı.',

  'pfx.note.title': 'PKCS#12 dosyasından okundu',
  'pfx.note.held': 'Dosyada {certs} ve {keys} var.',
  'pfx.note.heldNoKey': 'Dosyada {certs} var, özel anahtar yok.',
  'pfx.note.certs': '{count} sertifika',
  'pfx.note.keys': '{count} özel anahtar',
  'pfx.note.keyHidden': 'Özel anahtarlar hiçbir zaman gösterilmez ya da saklanmaz.',
  'pfx.note.friendlyName': 'Kolay ad',
  'pfx.note.certsProtection': 'Sertifikalar',
  'pfx.note.keyProtection': 'Özel anahtar',
  'pfx.note.integrity': 'Bütünlük denetimi',
  'pfx.note.notEncrypted': 'şifrelenmemiş',
  'pfx.note.noMac': 'yok',
  'pfx.note.iterations': '{count} yineleme',
  'pfx.note.notSupported': 'burada desteklenmiyor',
  'pfx.note.unverified': 'Bu dosyada bütünlük denetimi yok ve sertifikaları şifrelenmemiş: parolaya gerek kalmadan okundular, parola denetlenmedi.',
  'pfx.note.plainKey': {
    one: 'Özel anahtar şifrelenmeden saklanmış: dosyaya sahip olan herkes anahtara da sahip.',
    other: '{count} özel anahtar şifrelenmeden saklanmış: dosyaya sahip olan herkes anahtarlara da sahip.'
  },
  'pfx.strength.weak': 'zayıf',
  'pfx.strength.weakTitle': 'Tüm anahtarlar denenerek kırılabilen 40 ya da 56 bitlik bir anahtar. Herkese açık olan sertifikalar için zararsız; altındaki bir özel anahtar ise korunmuyor.',
  'pfx.strength.legacy': 'eski',
  'pfx.strength.legacyTitle': 'Güncel Windows ve Java sürümlerinin hâlâ okuduğu eski algoritmalar (3DES, RC2, SHA-1). Fırsat bulduğunuzda AES-256 ile dışa aktarın.',

  'pfx.key.match': 'Özel anahtar bu sertifikayla eşleşiyor',
  'pfx.key.mismatch': 'Özel anahtar bu sertifikayla eşleşmiyor',
  'pfx.key.mismatchBody': 'Bu sertifika ve bu anahtarla kurulan bir sunucu TLS el sıkışmasını tamamlayamaz.',
  'pfx.key.owner': 'Anahtar {name} sertifikasına ait.',
  'pfx.key.nokey': 'Dosyada özel anahtar yok: sunucunun anahtarı başka bir yerden alması gerekir.',
  'pfx.key.unsupported': '{algorithm} anahtarı tarayıcıda denetlenemez.',
  'pfx.key.encryptionUnsupported': 'Anahtarın şifrelemesi ({what}) burada desteklenmiyor, bu yüzden anahtar denetlenemez.',
  'pfx.key.iterationsUnsupported': 'Anahtarın parolası bu sayfanın çalıştırdığından daha çok yinelemeyle güçlendirilmiş, bu yüzden anahtar denetlenemez.',
  'pfx.key.failed': 'Özel anahtarın şifresi bu parolayla çözülemedi: kendine ait bir parolası olabilir ya da dosya bozuk.',
  'pfx.key.notChecked': 'Anahtar denetlenmedi. Denetlemek için dosyayı yeniden yükleyip “Özel anahtarın sertifikayla eşleştiğini denetle” kutusunu işaretleyin.',

  'pfx.fullchain': 'fullchain.pem indir',
  'pfx.fullchainHint': 'Sunucu sertifikası ve ara sertifikaları, sunucuların gönderdiği sırayla; kök sertifika ve özel anahtar olmadan.'
});

/**
 * Is this parse result a PKCS#12 bundle waiting for its password? (lib/x509.js
 * parseCertificates reports one as PKCS12_UNSUPPORTED and reads no certificate from it.)
 * @param {{ certificates: object[], warnings: Array<{ code: string }> }|null} result
 * @returns {boolean}
 */
export function isLockedPfx(result) {
  return !!result && !result.certificates.length && result.warnings.some((w) => w.code === 'PKCS12_UNSUPPORTED');
}

/**
 * The password dialog of a PKCS#12 file. `open(password, checkKey)` is called for each try and
 * resolves with a {@link import('../views/cert.js').CertLoad}; a PKCS12_BAD_PASSWORD result keeps
 * the dialog open with the reason, any other result closes it and is returned. Resolves null when
 * the dialog is cancelled (a try still running is then ignored).
 * @param {{ name: string, open: (password: string, checkKey: boolean) => Promise<{ result: { warnings: Array<{ code: string, detail?: string }> } }> }} opts
 * @returns {Promise<object|null>}
 */
export async function askPfxPassword({ name, open }) {
  let closed = false;
  let opened = null;
  let busy = false;
  // Enter in the password field or on the checkbox opens, like the Open button.
  const submitAndClose = () => {
    submit().then((done) => {
      if (done) modal.close('open');
    });
  };
  const password = textInput({
    label: t('pfx.password'),
    type: 'password',
    hint: t('pfx.passwordHint'),
    attrs: { 'data-role': 'pfx-password' },
    onEnter: submitAndClose
  });
  const check = checkbox({ label: t('pfx.checkKey'), hint: t('pfx.checkKeyHint') });
  check.input.dataset.role = 'pfx-check-key';
  check.input.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    submitAndClose();
  });
  const modal = Modal({
    title: t('pfx.title'),
    size: 'sm',
    className: 'pfx-dialog',
    content: h('div', { class: 'stack-sm', dataset: { role: 'pfx-dialog' } },
      h('p', { class: 'pfx-intro' }, t('pfx.intro', { name })),
      password.el,
      check.el,
      h('p', { class: 'muted text-sm pfx-privacy' }, Icon('lock', { size: 14 }), ' ', t('pfx.privacy'))),
    actions: [
      { label: t('common.cancel'), value: null, variant: 'secondary', dataset: { action: 'pfx-cancel' } },
      { label: t('pfx.open'), value: 'open', variant: 'primary', icon: 'unlock', dataset: { action: 'pfx-open' }, onClick: () => submit() }
    ],
    onClose: () => {
      closed = true;
      password.value = '';
    }
  });
  const openButton = () => modal.el.querySelector('[data-action="pfx-open"]');

  /** One try with the field's password; true when the dialog may close. */
  async function submit() {
    if (busy) return false;
    busy = true;
    password.setError(null);
    setButtonBusy(openButton(), true);
    let load;
    try {
      load = await open(password.value, check.checked);
    } finally {
      busy = false;
      if (!closed) setButtonBusy(openButton(), false);
    }
    if (closed) return false;
    const bad = load.result.warnings.find((w) => w.code === 'PKCS12_BAD_PASSWORD');
    if (bad) {
      password.setError(t(bad.detail === 'no-mac' ? 'pfx.wrong.noMac' : 'pfx.wrong.mac'));
      password.input.focus();
      password.input.select();
      return false;
    }
    opened = load;
    return true;
  }

  const value = await modal.open();
  return value === 'open' ? opened : null;
}

/**
 * "AES-256-CBC · PBKDF2-HMAC-SHA256 · 2,048 iterations" plus a weak / legacy badge; an encryption
 * this page cannot undo ends in "not supported here", and is only its name when that is all
 * that is known ("pbeWithSHAAnd128BitRC4 · not supported here").
 */
function schemeText(e) {
  if (!e.cipher) return `${e.unsupported} · ${t('pfx.note.notSupported')}`;
  let text = `${e.cipher} · ${e.kdf} · ${t('pfx.note.iterations', { count: e.iterations })}`;
  if (e.unsupported) text += ` · ${t('pfx.note.notSupported')}`;
  if (e.strength === 'weak' || e.strength === 'legacy') {
    return h('span', null, text, ' ', Badge(t(`pfx.strength.${e.strength}`), {
      variant: e.strength === 'weak' ? 'warn' : 'neutral', title: t(`pfx.strength.${e.strength}Title`), className: 'pfx-strength'
    }));
  }
  return text;
}

function macText(mac) {
  if (!mac) return t('pfx.note.noMac');
  const hmac = `HMAC-${mac.hash.replace('-', '')}`;
  const what = mac.kind === 'pbmac1' ? `PBMAC1 (${mac.kdf}, ${hmac})` : hmac;
  return `${what} · ${t('pfx.note.iterations', { count: mac.iterations })}`;
}

/**
 * What a PKCS#12 bundle held and how it was protected, with the key check's verdict
 * (lib/x509.js Pkcs12Summary): an info callout, plus an error callout when the key belongs to
 * another certificate and a warning when it did not decrypt.
 * @param {import('../lib/x509.js').Pkcs12Summary} summary
 * @param {{ actions?: Array<Node|null>, certName?: (cert: object) => string }} [opts] actions: e.g.
 *   Download fullchain.pem; certName: how to name the key's owner (default: its subject CN)
 * @returns {HTMLElement}
 */
export function PfxNote(summary, { actions = [], certName = (c) => c.subjectCN || c.subjectDN || '—' } = {}) {
  const certs = t('pfx.note.certs', { count: summary.certificates });
  const held = summary.keys
    ? t('pfx.note.held', { certs, keys: t('pfx.note.keys', { count: summary.keys }) })
    : t('pfx.note.heldNoKey', { certs });
  const facts = [];
  if (summary.friendlyName) facts.push({ key: t('pfx.note.friendlyName'), value: summary.friendlyName });
  facts.push({
    key: t('pfx.note.certsProtection'),
    value: summary.encryption.length ? summary.encryption.map(schemeText) : t('pfx.note.notEncrypted')
  });
  if (summary.keys) {
    const plain = summary.unencryptedKeys ? [t('pfx.note.notEncrypted')] : [];
    facts.push({ key: t('pfx.note.keyProtection'), value: [...summary.keyEncryption.map(schemeText), ...plain] });
  }
  facts.push({ key: t('pfx.note.integrity'), value: macText(summary.mac) });

  const kc = summary.keyCheck;
  const muted = (text) => h('p', { class: 'muted text-sm pfx-key-verdict' }, text);
  // The key is encrypted in a way this page cannot undo: ticking the key check would not help.
  const locked = (what) => t(what === 'iterations' ? 'pfx.key.iterationsUnsupported' : 'pfx.key.encryptionUnsupported', { what });
  const allLocked = !summary.unencryptedKeys && summary.keyEncryption.length && summary.keyEncryption.every((e) => e.unsupported);
  let verdict = null;
  const extra = [];
  if (!kc) {
    if (summary.keys && summary.certificates) verdict = muted(allLocked ? locked(summary.keyEncryption[0].unsupported) : t('pfx.key.notChecked'));
  } else if (kc.status === 'nocert') {
    // No certificate was read: the alerts above say why; a key check has nothing to say.
  } else if (kc.status === 'match') {
    verdict = h('div', { class: 'pfx-key-verdict cluster' },
      Badge(t('pfx.key.match'), { variant: 'ok', icon: 'check-circle' }),
      kc.algorithm ? h('span', { class: 'muted text-sm mono' }, kc.algorithm) : null);
  } else if (kc.status === 'mismatch') {
    const a = Alert({
      variant: 'error', compact: true, icon: 'key', title: t('pfx.key.mismatch'),
      message: [t('pfx.key.mismatchBody'), kc.owner ? t('pfx.key.owner', { name: certName(kc.owner) }) : null].filter(Boolean).join(' ')
    });
    extra.push(a);
  } else if (kc.status === 'failed') {
    extra.push(Alert({ variant: 'warn', compact: true, icon: 'key', message: t('pfx.key.failed') }));
  } else if (kc.status === 'unsupported-encryption') {
    verdict = muted(locked(kc.encryption || '?'));
  } else {
    verdict = muted(kc.status === 'nokey' ? t('pfx.key.nokey') : t('pfx.key.unsupported', { algorithm: kc.algorithm || '?' }));
  }
  const warnings = [
    !summary.passwordVerified ? t('pfx.note.unverified') : null,
    summary.unencryptedKeys ? t('pfx.note.plainKey', { count: summary.unencryptedKeys }) : null
  ].filter(Boolean).map((text) => h('p', { class: 'pfx-warning text-sm' }, Icon('alert', { size: 14 }), ' ', text));

  const info = Alert({
    variant: 'info',
    compact: true,
    icon: 'lock',
    title: t('pfx.note.title'),
    message: `${held} ${t('pfx.note.keyHidden')}`,
    children: [KeyValueList(facts, { className: 'pfx-facts' }), ...warnings, verdict],
    actions: (actions || []).filter(Boolean)
  });
  return h('div', {
    class: 'pfx-note stack-sm',
    dataset: { pfxNote: '', keyCheck: kc ? kc.status : 'none' },
    attrs: { tabindex: -1 }
  }, info, extra);
}
