# Summary

> **CVE status:** requested, pending assignment. This finding is published as
> [GHSA-3gx3-r874-5pp4](https://github.com/philips/supernote-obsidian-plugin/security/advisories/GHSA-3gx3-r874-5pp4). On CVE assignment this repository is renamed
> `CVE-YYYY-NNNNN-supernote-obsidian-plugin-PoC` and this banner is replaced with the CVE link.

| | |
|---|---|
| Researcher | Dostxodjayev Abdullox ([@squeeze440](https://github.com/squeeze440)) |
| Advisory | [GHSA-3gx3-r874-5pp4](https://github.com/philips/supernote-obsidian-plugin/security/advisories/GHSA-3gx3-r874-5pp4) |
| CVSS 3.1 | 5.6 (Medium) |
| Weakness | CWE-22, CWE-73 |

---

## Summary

Path Traversal in the device auto-sync feature of the Supernote (Unofficial) Obsidian plugin (`philips/supernote-obsidian-plugin`) v2.9.1 allows a malicious or rogue "Supernote" device (or an on-path/on-LAN attacker impersonating the paired device's IP) to make the victim's Obsidian client write an arbitrary new file anywhere the desktop process can write — including outside the configured sync folder and outside the vault itself — via a crafted `uri` field in the device's directory-listing response.

## Product

`philips/supernote-obsidian-plugin` ("Supernote (Unofficial)"), an Obsidian.md community plugin that syncs a physical Supernote e-ink device's notes into a vault over the device's local "Browse and Access" HTTP server (`http://<device-ip>:8089`, no authentication, by design of the device feature).

## Tested Version

- Plugin: v2.9.1, commit `48db5bf4dcfb100632c84699c830c1309da1abb9`
- Submodule `supernote-typescript`: commit `195415b3a1f74147...`  (not itself implicated — the bug is entirely in the plugin's own sync-planning code)
- Host app: Obsidian desktop 1.13.4 (real binary, dynamically tested)

## Estimated CVSS v3.1

**5.6 Medium** — `CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N`

- `AV:A` — the device's HTTP server is plaintext, unauthenticated, and configured by a bare IPv4 address (`IP_VALIDATION_PATTERN`, `src/settings.ts:6`); reaching it as "the device" requires LAN-adjacent network position (rogue AP, ARP spoofing, or claiming the IP), not arbitrary remote access.
- `AC:H` — exploitation depends on the attacker already occupying that network position when the victim's plugin talks to `directConnectIP:8089`; it isn't a one-shot remote trigger.
- `UI:R` — requires the victim to run "Sync supernote notes now" (or have the auto-sync toggle already enabled) while pointed at the attacker-controlled endpoint.
- `S:C` — the vulnerable component is a vault-scoped Obsidian plugin; the write lands outside the vault entirely, on the underlying host filesystem, which is a different security scope.
- `C:N` — this is a write-only primitive; nothing is read back to the attacker.
- `I:H` — attacker-controlled bytes land at an attacker-chosen path with attacker-chosen filename. Bounded caveat: `writeBinaryAt()` (`src/syncEngine.ts:40-47`) only takes the *create* branch for paths not already tracked in the plugin's own sync manifest, and Obsidian's `Vault.createBinary()` itself refuses to silently clobber a file that already physically exists at the resolved path (confirmed empirically — see PoC) — so this is "plant a new file anywhere," not "overwrite any existing file."
- `A:N` — no availability impact demonstrated.

## Details

`runDeviceSync()` (`src/syncEngine.ts:100-196`) lists the paired device's files via `scanDeviceSupernoteTree()` (`src/FileListModal.ts:53-68`), which recurses the device's own HTTP directory listing and keeps any entry whose **`name`** matches `/\.(note|spd)$/i` (`src/FileListModal.ts:46,63`). The **`uri`** field of each entry — a separate, independently-controlled string in the same JSON object returned by the device — is never validated against `name` or against anything else.

That raw `uri` is then fed straight into `deviceUriToVaultPath()` (`src/deviceSync.ts:153-161`):

```ts
const INVALID_FILENAME_CHARS = /[\\:*?"<>|]/g;   // deviceSync.ts:144

export function deviceUriToVaultPath(syncFolder: string, deviceUri: string): string {
    const segments = deviceUri
        .split('/')
        .filter((s) => s.length > 0)
        .map((s) => s.replace(INVALID_FILENAME_CHARS, '_'));

    const cleanRoot = syncFolder.replace(/^\/+|\/+$/g, '');
    return cleanRoot ? `${cleanRoot}/${segments.join('/')}` : segments.join('/');
}
```

`INVALID_FILENAME_CHARS` strips `\ : * ? " < > |` but never strips or rejects `..` path segments. A device `uri` of `/../../PWNED.txt` survives untouched and is joined onto the configured sync folder (default `"Supernote sync"`) to produce `vaultPath = "Supernote sync/../../PWNED.txt"`.

`syncEngine.ts:128` computes this `vaultPath` from the listing's raw `uri`, then `ensureFolder()`/`writeBinaryAt()` (`syncEngine.ts:146-148`, `21-47`) pass it straight to `app.vault.getAbstractFileByPath()` / `createBinary()` / `modifyBinary()` with no traversal check. Obsidian's own path resolution then normalizes the `..` segments against the real vault directory on disk, landing the write above the sync folder — and, with enough `../` segments, above the vault root entirely, onto the host filesystem, in the OS user's own permission scope.

**Sibling check**: every other vault-write sink in this codebase (`src/main.ts` — screen-mirror capture, PDF/markdown import, "attach to note", `DownloadListModal` in `src/FileListModal.ts:245-246`) builds its destination path via Obsidian's own `app.fileManager.getAvailablePathForAttachment(file.name)`, which only ever consumes the device's `name` field and is not exploitable this way. `deviceUriToVaultPath()` in the newer auto-sync feature is the only sink that instead hand-rolls a path from the device's `uri` field, and it's the one that skipped `..` sanitization — a clean case of "checked on every sibling but this one."

The plugin's own settings UI states: *"The sync command never writes anywhere outside this folder"* (`src/settings.ts`, Sync folder description) — this PoC directly falsifies that guarantee.

## Proof of Concept

Dynamically confirmed end-to-end against a real, unmodified Obsidian 1.13.4 desktop binary (Xvfb + fluxbox + xdotool + scrot), running the plugin's actual compiled `main.js` — no mocking of plugin code.

1. Built the plugin from source (`./scripts/build`) and loaded it into a fresh test vault (`Supernote (Unofficial)` v2.9.1, enabled via "Trust author and enable plugins").
2. Set plugin setting `Supernote IP address` to `127.0.0.1`, left `Sync folder` at its default `Supernote sync`.
3. Stood up a one-file Node mock of the device's "Browse and Access" server on `127.0.0.1:8089`, simulating a malicious/rogue device. Its directory listing returns:
   ```json
   {"name":"Quick notes.note","size":61,"date":"2026-07-31 00:00:00",
    "uri":"/../../PWNED_BY_DEVICE_SYNC.txt","extension":"note","isDirectory":false}
   ```
   (`name` passes the `.note` extension filter; `uri` carries the traversal.) Any GET is answered 200 with the file bytes — real HTTP clients normalize `..` out of the outgoing *request* path before it hits the wire (RFC 3986), which is irrelevant here since the vulnerable code computes the *write* path from the original JSON string, not from the normalized request URL.
4. Ran the command palette action **"Supernote (Unofficial): Sync supernote notes now"**.
5. Result: a new file, `PWNED_BY_DEVICE_SYNC.txt`, containing the attacker's bytes, was created **one directory above the vault root** (sibling of `testvault/`, outside the vault entirely). The plugin's own `data.json` recorded the computed path verbatim: `"vaultPath": "Supernote sync/../../PWNED_BY_DEVICE_SYNC.txt"`.

Evidence (genuine captures, `~/engagements/supernote-obsidian-plugin/evidence/`):
- `01-vault-escape-file-write.png` — real terminal: `ls -la testvault/ PWNED_BY_DEVICE_SYNC.txt` showing the file as a sibling of the vault directory, plus its attacker-controlled content via `cat`.
- `02-plugin-data-json-vaultpath.png` — the plugin's own persisted sync-state file recording `"vaultPath": "Supernote sync/../../PWNED_BY_DEVICE_SYNC.txt"`.
- `03-plugin-settings-security-claim.png` — the plugin's settings UI claiming the sync command "never writes anywhere outside this folder."

## Impact

An attacker who can respond as the victim's configured Supernote device (LAN-adjacent: rogue AP, ARP spoofing, or claiming the device's IP) can make the victim's Obsidian client create a new, attacker-controlled file at any filesystem path the desktop process can write to — inside the vault (e.g. a brand-new file under `.obsidian/plugins/<new-id>/`, laying groundwork for further plugin-trust abuse) or entirely outside it (e.g. `~/.config/autostart/*.desktop`, a new crontab drop-in, or any other location where a *new* file — not an overwrite — is enough to gain execution or persistence). It cannot silently overwrite a file that already exists at the resolved path (Obsidian's `createBinary` throws "File already exists" in that case, confirmed empirically), which bounds the primitive to net-new file planting rather than universal overwrite.

## Weaknesses

- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-73**: External Control of File Name or Path (the device-supplied `uri` directly determines the on-disk destination)

## Remediation

In `deviceUriToVaultPath()` (`src/deviceSync.ts:153-161`), reject or strip `..` (and empty/`.`-only) path segments after splitting `deviceUri`, e.g.:

```ts
const segments = deviceUri
    .split('/')
    .filter((s) => s.length > 0 && s !== '.' && s !== '..')
    .map((s) => s.replace(INVALID_FILENAME_CHARS, '_'));
```

Additionally, `scanDeviceSupernoteTree()` (`src/FileListModal.ts:63`) should validate that a listing entry's `uri` is consistent with its `name` (e.g. `uri` ends with the same filename), rather than trusting the two fields independently — the same class of defense already implicitly relied on everywhere else in the codebase, which builds paths only from `name`/`basename` via `getAvailablePathForAttachment()`.

## Credit

Dostxodjayev Abdullox

## Reporting Channel

No `SECURITY.md` is present in this repository. GitHub private vulnerability reporting is confirmed **enabled** for `philips/supernote-obsidian-plugin` (`gh api repos/philips/supernote-obsidian-plugin/private-vulnerability-reporting --jq .enabled` → `true`; 0 prior published security advisories). Standard GHSA flow applies: `https://github.com/philips/supernote-obsidian-plugin/security/advisories/new`.
