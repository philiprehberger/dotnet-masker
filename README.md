# Philiprehberger.Masker

[![CI](https://github.com/philiprehberger/dotnet-masker/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/dotnet-masker/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Philiprehberger.Masker.svg)](https://www.nuget.org/packages/Philiprehberger.Masker)
[![License](https://img.shields.io/github/license/philiprehberger/dotnet-masker)](LICENSE)

Mask and redact sensitive data in strings and objects for safe logging.

## Install

```bash
dotnet add package Philiprehberger.Masker
```

## Usage

### Built-In Patterns

```csharp
using Philiprehberger.Masker;

var input = "Card: 4111-1111-1111-1234";
var masked = Masker.Mask(input, MaskPattern.CreditCard);
// "Card: ************1234"
```

### Mask All Patterns at Once

```csharp
var log = "User john@example.com called with SSN 123-45-6789";
var safe = Masker.MaskAll(log);
// "User j***@example.com called with SSN ***-**-6789"
```

### Custom Regex Pattern

```csharp
using System.Text.RegularExpressions;

var pattern = new Regex(@"API_KEY_\w+");
var result = Masker.Mask("Token: API_KEY_abc123xyz", pattern, revealStart: 0, revealEnd: 4);
// "Token: ***********xyz"
```

### Object Masking

```csharp
public class UserDto
{
    public string Name { get; set; } = "";

    [SensitiveData]
    public string Password { get; set; } = "";

    [SensitiveData(PatternName = "Email")]
    public string Email { get; set; } = "";
}

var user = new UserDto
{
    Name = "Alice",
    Password = "s3cret!pass",
    Email = "alice@example.com"
};

var safe = ObjectMasker.MaskObject(user);
// safe.Name     => "Alice"
// safe.Password => "*******pass"
// safe.Email    => "a****@example.com"
```

## API

### `Masker`

| Method | Description |
|--------|-------------|
| `Mask(string input, MaskPattern pattern)` | Mask using a built-in pattern |
| `Mask(string input, Regex pattern, int revealStart, int revealEnd)` | Mask using a custom regex with reveal options |
| `MaskAll(string input)` | Apply all built-in patterns to the input |

### `MaskPattern`

| Property | Description |
|----------|-------------|
| `CreditCard` | 13-19 digit card numbers, reveals last 4 |
| `Email` | Email addresses, masks local part |
| `Phone` | US phone numbers, reveals last 4 digits |
| `SSN` | Social Security Numbers, reveals last 4 |
| `JWT` | JSON Web Tokens, fully redacted |
| `BearerToken` | Bearer auth tokens, fully redacted |
| `ConnectionString` | Password/secret values in connection strings |

### `ObjectMasker`

| Method | Description |
|--------|-------------|
| `MaskObject<T>(T obj)` | Create a masked clone of an object |

### `SensitiveDataAttribute`

| Property | Description |
|----------|-------------|
| `PatternName` | Optional pattern name to apply (e.g. "Email", "CreditCard") |

### `MaskerOptions`

| Property | Default | Description |
|----------|---------|-------------|
| `MaskChar` | `'*'` | Character used for masking |
| `RevealLength` | `4` | Number of characters to leave visible |
| `RevealEnd` | `true` | Reveal at end (`true`) or start (`false`) |

## License

MIT
