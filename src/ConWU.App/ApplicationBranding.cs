namespace StreamLink;

static class ApplicationBranding
{
    public static Icon CreateIcon()
    {
        using var stream=typeof(ApplicationBranding).Assembly.GetManifestResourceStream("ConWU.AppIcon.ico")??throw new IOException("Application icon is missing");
        using var icon=new Icon(stream,32,32);
        return (Icon)icon.Clone();
    }
}
