namespace Philiprehberger.Masker;

/// <summary>
/// Configuration options for masking operations.
/// </summary>
/// <param name="MaskChar">The character used to replace sensitive data. Defaults to <c>'*'</c>.</param>
/// <param name="RevealLength">The number of characters to leave unmasked. Defaults to <c>4</c>.</param>
/// <param name="RevealEnd">
/// When <c>true</c>, the unmasked characters are at the end of the value.
/// When <c>false</c>, they are at the beginning. Defaults to <c>true</c>.
/// </param>
public record MaskerOptions(
    char MaskChar = '*',
    int RevealLength = 4,
    bool RevealEnd = true);
