namespace StreamLink;

static class ApplicationVersion
{
    public static Version Current { get; } = typeof(ApplicationVersion).Assembly.GetName().Version!;
    public static string Number => Current.ToString(3);
    public static string Release => (typeof(ApplicationVersion).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).Cast<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion??Number).Split('+')[0];
}
