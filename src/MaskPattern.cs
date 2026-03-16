using System.Text.RegularExpressions;

namespace Philiprehberger.Masker;

/// <summary>
/// Represents a named masking pattern with a regular expression and a function
/// that produces the masked replacement for each match.
/// </summary>
/// <param name="Name">A human-readable name for the pattern (e.g. "CreditCard").</param>
/// <param name="Pattern">The regular expression used to detect sensitive data.</param>
/// <param name="MaskFunction">
/// A function that receives the matched string and returns the masked replacement.
/// </param>
public record MaskPattern(string Name, Regex Pattern, Func<string, string> MaskFunction)
{
    /// <summary>
    /// Matches credit card numbers (13-19 digits, optionally separated by spaces or dashes).
    /// Reveals the last 4 digits.
    /// </summary>
    public static MaskPattern CreditCard { get; } = new(
        "CreditCard",
        new Regex(@"\b(?:\d[\s-]*?){13,19}\b", RegexOptions.Compiled),
        match =>
        {
            var digits = new string(match.Where(char.IsDigit).ToArray());
            if (digits.Length < 4) return new string('*', digits.Length);
            return new string('*', digits.Length - 4) + digits[^4..];
        });

    /// <summary>
    /// Matches email addresses. Masks the local part, preserving the first character and the domain.
    /// </summary>
    public static MaskPattern Email { get; } = new(
        "Email",
        new Regex(@"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled),
        match =>
        {
            var atIndex = match.IndexOf('@');
            if (atIndex <= 1) return "***" + match[atIndex..];
            return match[0] + new string('*', atIndex - 1) + match[atIndex..];
        });

    /// <summary>
    /// Matches US phone numbers in common formats (e.g. 123-456-7890, (123) 456-7890, +1 123 456 7890).
    /// Reveals the last 4 digits.
    /// </summary>
    public static MaskPattern Phone { get; } = new(
        "Phone",
        new Regex(@"(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b", RegexOptions.Compiled),
        match =>
        {
            var digits = new string(match.Where(char.IsDigit).ToArray());
            if (digits.Length < 4) return new string('*', digits.Length);
            return new string('*', digits.Length - 4) + digits[^4..];
        });

    /// <summary>
    /// Matches US Social Security Numbers (e.g. 123-45-6789). Reveals the last 4 digits.
    /// </summary>
    public static MaskPattern SSN { get; } = new(
        "SSN",
        new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled),
        match => "***-**-" + match[^4..]);

    /// <summary>
    /// Matches JSON Web Tokens (three base64url segments separated by dots).
    /// Replaces the entire token with a placeholder.
    /// </summary>
    public static MaskPattern JWT { get; } = new(
        "JWT",
        new Regex(@"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", RegexOptions.Compiled),
        _ => "[REDACTED_JWT]");

    /// <summary>
    /// Matches Bearer tokens in authorization headers. Replaces the token value.
    /// </summary>
    public static MaskPattern BearerToken { get; } = new(
        "BearerToken",
        new Regex(@"Bearer\s+[a-zA-Z0-9_\-.~+/]+=*", RegexOptions.Compiled),
        _ => "Bearer [REDACTED]");

    /// <summary>
    /// Matches common connection string patterns containing passwords or secrets.
    /// Masks the password value while preserving the key.
    /// </summary>
    public static MaskPattern ConnectionString { get; } = new(
        "ConnectionString",
        new Regex(@"(?i)(password|pwd|secret|key)\s*=\s*[^;""'\s]+", RegexOptions.Compiled),
        match =>
        {
            var eqIndex = match.IndexOf('=');
            return match[..(eqIndex + 1)] + "***";
        });
}
