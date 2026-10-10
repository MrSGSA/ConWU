namespace StreamLink;

static class DesktopVersion
{
    public static Version Current { get; } = typeof(MainWindow).Assembly.GetName().Version!;
    public static string Number => Current.ToString(3);
    public static string Release => Number + "-preview";
}
