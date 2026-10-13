namespace StreamLink;

public static class ServiceInstallTransaction
{
    // Rollback authorizations and the old executable independently. A failure
    // restoring one must never suppress the other recovery attempt.
    public static async Task Execute(Func<Task> apply,Func<Task> restoreAuthorization,Func<Task> restoreService)
    {
        try { await apply(); }
        catch(Exception candidate) {
            var failures=new List<Exception>{candidate};
            try { await restoreAuthorization(); } catch(Exception ex) { failures.Add(ex); }
            try { await restoreService(); } catch(Exception ex) { failures.Add(ex); }
            if(failures.Count>1)throw new IOException("候选安装失败；恢复也未全部完成："+string.Join("；",failures.Select(e=>e.Message)),new AggregateException(failures));
            throw new IOException("候选安装未通过本地就绪检查，已恢复原服务状态和 UI 授权",candidate);
        }
    }
}
