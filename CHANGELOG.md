# Changelog

## 0.1.7 (2026-03-26)

- Add Sponsor badge to README
- Fix License section format
- Add trailing period to description

## 0.1.6 (2026-03-23)

- Sync .csproj description with README

## 0.1.5 (2026-03-22)

- Add dates to changelog entries

## 0.1.4 (2026-03-17)

- Rename Install section to Installation in README per package guide

## 0.1.3 (2026-03-16)

- Add Development section to README
- Add GenerateDocumentationFile, RepositoryType, PackageReadmeFile to .csproj

## 0.1.1 (2026-03-16)

- Fix: add NuGet publishing secret

## 0.1.0 (2026-03-15)

- Initial release
- `Masker` — static API for masking strings with built-in or custom patterns
- `MaskPattern` — built-in patterns for credit cards, emails, phones, SSNs, JWTs, bearer tokens, and connection strings
- `ObjectMasker` — mask sensitive properties in object graphs via `[SensitiveData]` attribute
- `MaskerOptions` — configuration record for mask character, reveal length, and reveal position
