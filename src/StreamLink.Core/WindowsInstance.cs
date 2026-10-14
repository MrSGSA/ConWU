namespace StreamLink.Core;

// Explicit isolation for real installed-package acceptance. The default is
// immutable in ordinary launches; validation never shares its service, pipes,
// protected profile or installation directory with the user's live network.
public static class WindowsInstance
{
    static string? validation;
    public static string Name => validation == null ? PersonalFeature.InstanceName : "StreamLink-Validation-" + validation;
    public static bool IsValidation => validation != null;
    public static string? ValidationId => validation;
    public static string ProfileRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StreamLink-Validation", validation ?? throw new InvalidOperationException());
    public static string InstallParent => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "StreamLink-Validation", validation ?? throw new InvalidOperationException());
    public static void ConfigureValidation(string value)
    {
        if (!Guid.TryParseExact(value,"N",out var id) || id == Guid.Empty) throw new ArgumentException("Validation scope requires a nonzero canonical GUID");
        if (validation != null && validation != value) throw new InvalidOperationException("An instance cannot change its validation identity");
        validation=value;
    }
}
