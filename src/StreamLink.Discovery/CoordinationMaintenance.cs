namespace StreamLink.Discovery;

public static class CoordinationMaintenance
{
    public const string Usage = "coordinator backup|inspect|restore <备份.slcoord> [--data <协调数据目录>] [--confirm-rollback（仅恢复）]";
    public static object Execute(string[] args, string defaultRoot)
    {
        if (args.Length < 2 || args[0] is not ("backup" or "inspect" or "restore")) throw new ArgumentException(Usage);
        string root = defaultRoot; bool confirm = false, hasRoot = false;
        for (int i = 2; i < args.Length; i++) {
            if (args[i] == "--data" && !hasRoot && i + 1 < args.Length && args[0] != "inspect") { root = args[++i]; hasRoot = true; }
            else if (args[i] == "--confirm-rollback" && !confirm && args[0] == "restore") confirm = true;
            else throw new ArgumentException(Usage);
        }
        root = Path.GetFullPath(root); string archive = Path.GetFullPath(args[1]);
        return args[0] switch {
            "inspect" => CoordinationBackup.Inspect(archive),
            "backup" => CoordinationBackup.Create(root, archive),
            _ => CoordinationBackup.Restore(root, archive, confirm)
        };
    }
}
