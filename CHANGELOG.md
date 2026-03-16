# Changelog

## 0.1.1 (2026-03-16)

- Fix: add NuGet publishing secret

## 0.1.0 (2026-03-15)

- Initial release
- `Masker` — static API for masking strings with built-in or custom patterns
- `MaskPattern` — built-in patterns for credit cards, emails, phones, SSNs, JWTs, bearer tokens, and connection strings
- `ObjectMasker` — mask sensitive properties in object graphs via `[SensitiveData]` attribute
- `MaskerOptions` — configuration record for mask character, reveal length, and reveal position
