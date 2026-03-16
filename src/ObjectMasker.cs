using System.Reflection;

namespace Philiprehberger.Masker;

/// <summary>
/// Marks a property as containing sensitive data that should be masked
/// when processed by <see cref="ObjectMasker"/>.
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class SensitiveDataAttribute : Attribute
{
    /// <summary>
    /// An optional <see cref="MaskPattern"/> name to apply. When <c>null</c>,
    /// the entire string value is masked.
    /// </summary>
    public string? PatternName { get; init; }
}

/// <summary>
/// Provides methods for masking sensitive data within object graphs using reflection.
/// Properties decorated with <see cref="SensitiveDataAttribute"/> are automatically masked.
/// </summary>
public static class ObjectMasker
{
    private static readonly Dictionary<string, MaskPattern> PatternsByName = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CreditCard"] = MaskPattern.CreditCard,
        ["Email"] = MaskPattern.Email,
        ["Phone"] = MaskPattern.Phone,
        ["SSN"] = MaskPattern.SSN,
        ["JWT"] = MaskPattern.JWT,
        ["BearerToken"] = MaskPattern.BearerToken,
        ["ConnectionString"] = MaskPattern.ConnectionString,
    };

    /// <summary>
    /// Creates a shallow clone of the object with all properties marked with
    /// <see cref="SensitiveDataAttribute"/> masked.
    /// </summary>
    /// <typeparam name="T">The type of the object to mask. Must have a parameterless constructor.</typeparam>
    /// <param name="obj">The source object. If <c>null</c>, returns <c>default</c>.</param>
    /// <returns>A new instance of <typeparamref name="T"/> with sensitive properties masked.</returns>
    public static T? MaskObject<T>(T? obj) where T : class, new()
    {
        if (obj is null)
            return default;

        var clone = new T();
        var properties = typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance);

        foreach (var prop in properties)
        {
            if (!prop.CanRead || !prop.CanWrite)
                continue;

            var value = prop.GetValue(obj);
            var sensitiveAttr = prop.GetCustomAttribute<SensitiveDataAttribute>();

            if (sensitiveAttr is not null && value is string strValue)
            {
                var masked = MaskPropertyValue(strValue, sensitiveAttr);
                prop.SetValue(clone, masked);
            }
            else
            {
                prop.SetValue(clone, value);
            }
        }

        return clone;
    }

    private static string MaskPropertyValue(string value, SensitiveDataAttribute attr)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        if (attr.PatternName is not null && PatternsByName.TryGetValue(attr.PatternName, out var pattern))
        {
            return Masker.Mask(value, pattern);
        }

        // Full mask: reveal last 4 characters if long enough
        if (value.Length <= 4)
            return new string('*', value.Length);

        return new string('*', value.Length - 4) + value[^4..];
    }
}
