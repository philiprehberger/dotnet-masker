using System.Text.RegularExpressions;

namespace Philiprehberger.Masker;

/// <summary>
/// Provides static methods for masking and redacting sensitive data in strings.
/// </summary>
public static class Masker
{
    private static readonly MaskPattern[] BuiltInPatterns =
    [
        MaskPattern.JWT,
        MaskPattern.BearerToken,
        MaskPattern.CreditCard,
        MaskPattern.SSN,
        MaskPattern.Email,
        MaskPattern.Phone,
        MaskPattern.ConnectionString,
    ];

    /// <summary>
    /// Masks sensitive data in the input string using a built-in <see cref="MaskPattern"/>.
    /// </summary>
    /// <param name="input">The string to mask.</param>
    /// <param name="pattern">The built-in pattern to apply.</param>
    /// <returns>The input string with matched portions replaced by their masked equivalents.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="input"/> or <paramref name="pattern"/> is <c>null</c>.
    /// </exception>
    public static string Mask(string input, MaskPattern pattern)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(pattern);

        return pattern.Pattern.Replace(input, match => pattern.MaskFunction(match.Value));
    }

    /// <summary>
    /// Masks sensitive data in the input string using a custom regular expression.
    /// Characters outside the revealed portions are replaced with <c>'*'</c>.
    /// </summary>
    /// <param name="input">The string to mask.</param>
    /// <param name="pattern">A regular expression identifying the sensitive portions.</param>
    /// <param name="revealStart">The number of characters to leave unmasked at the start of each match. Defaults to <c>0</c>.</param>
    /// <param name="revealEnd">The number of characters to leave unmasked at the end of each match. Defaults to <c>4</c>.</param>
    /// <returns>The input string with matched portions partially masked.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="input"/> or <paramref name="pattern"/> is <c>null</c>.
    /// </exception>
    public static string Mask(string input, Regex pattern, int revealStart = 0, int revealEnd = 4)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(pattern);

        return pattern.Replace(input, match =>
        {
            var value = match.Value;
            if (value.Length <= revealStart + revealEnd)
                return value;

            var start = revealStart > 0 ? value[..revealStart] : "";
            var end = revealEnd > 0 ? value[^revealEnd..] : "";
            var maskedLength = value.Length - revealStart - revealEnd;

            return start + new string('*', maskedLength) + end;
        });
    }

    /// <summary>
    /// Applies all built-in masking patterns to the input string.
    /// Patterns are applied in a fixed order: JWT, BearerToken, CreditCard, SSN, Email, Phone, ConnectionString.
    /// </summary>
    /// <param name="input">The string to mask.</param>
    /// <returns>The input string with all recognized sensitive data masked.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="input"/> is <c>null</c>.</exception>
    public static string MaskAll(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var result = input;
        foreach (var pattern in BuiltInPatterns)
        {
            result = pattern.Pattern.Replace(result, match => pattern.MaskFunction(match.Value));
        }

        return result;
    }
}
