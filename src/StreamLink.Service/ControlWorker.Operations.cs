using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;
public sealed partial class ControlWorker
{
    sealed class Operation(Guid id,string command,string digest,CancellationTokenSource stop)
    {
        public Guid Id {get;}=id;
        public string Command {get;}=command;
        public string Digest {get;}=digest;
        public CancellationTokenSource Stop {get;}=stop;
        public TaskCompletionSource Completion {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ControlOperationStatus State {get;set;}=new(id,command,"排队",false,true);
        public bool Completed,Cancelable=true;
        public bool UserCancelled;
        public CancellationToken ServiceLifetime;
        public string DisplayCommand {get;set;}=command;
    }
    readonly object operationGate=new();
    readonly Dictionary<Guid,Operation> operations=new();
    readonly CancellationTokenSource disposing=new();
    ControlOperationStatus? operationStatus;
    int disposed;
    static readonly object quarantineGate=new();
    static readonly List<ControlWorker> quarantinedWorkers=[];
    void ReleaseControlOwnership(){
        if(uiEntryResolver.IsValueCreated)uiEntryResolver.Value.Dispose();
        uiDirectHost.Clear();ResetUiPair("后台已退出");
        if(Volatile.Read(ref resourceShutdownUnproven)){
            // Strongly retain the worker, its failed owners and file lock.
            // A FileStream finalizer must not admit a second owner in this PID.
            lock(quarantineGate)quarantinedWorkers.Add(this);
            return;
        }
        lease.Dispose();
    }
    Operation OpenOperation(ControlRequest request,CancellationToken token,out bool duplicate,UiOperation? ui=null)
    {
        lock(operationGate){
            duplicate=false;
            token.ThrowIfCancellationRequested();disposing.Token.ThrowIfCancellationRequested();
            Guid id=request.OperationId==Guid.Empty?Guid.NewGuid():request.OperationId;
            string digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { Request=request,Ui=ui })));
            if(operations.TryGetValue(id,out var prior)){
                if(prior.Command!=request.Command||prior.Digest!=digest)throw new IOException("操作ID已被不同请求使用");
                duplicate=true;return prior; // Read progress, never repeat mutation.
            }
            if(operations.Values.Count(o=>!o.Completed)>=8)throw new IOException("已有太多控制操作，稍后重试");
            if(operations.Count>=64){var old=operations.Values.FirstOrDefault(o=>o.Completed);if(old!=null)operations.Remove(old.Id);else throw new IOException("后台操作队列已满，请等待当前操作完成");}
            // An authenticated UI request hands ownership to the service. Closing
            // a tab or expiring a pipe must not cancel an accepted mutation.
            // ServeUi passes the service lifetime here, never its response timer.
            var entry=new Operation(id,request.Command,digest,CancellationTokenSource.CreateLinkedTokenSource(token,disposing.Token));
            if(ui!=null)entry.ServiceLifetime=token;
            if(ui!=null)entry.Stop.CancelAfter(TimeSpan.FromSeconds(90));
            if(ui?.Network is {} action)entry.DisplayCommand=request.Command+":"+action.Action;
            entry.State=entry.State with{Command=entry.DisplayCommand};
            operations.Add(id,entry);Volatile.Write(ref operationStatus,entry.State);PublishReply();return entry;
        }
    }
    void SetOperation(Operation operation,string phase,bool cancelable){lock(operationGate){operation.Cancelable=cancelable;operation.State=new(operation.Id,operation.DisplayCommand,phase,false,cancelable);Volatile.Write(ref operationStatus,operation.State);}PublishReply();}
    void CompleteOperation(Operation operation,string error=""){
        lock(operationGate){if(operation.Completed)return;operation.Completed=true;operation.Cancelable=false;operation.Stop.Dispose();
            operation.State=new(operation.Id,operation.DisplayCommand,error.Length==0?"已完成":"未完成",true,false,error);
            if(operationStatus?.Id==operation.Id)Volatile.Write(ref operationStatus,operation.State);operation.Completion.TrySetResult();}
    }
    ControlReply CancelOperation(Guid id){
        lock(operationGate){if(id==Guid.Empty||!operations.TryGetValue(id,out var op)||op.Completed)return Reply("未找到运行中的操作");
            if(!op.Cancelable)return Reply("操作已进入资源退出阶段，可取消界面等待，但不能撤销已请求的网络停止");op.UserCancelled=true;op.Stop.Cancel();}
        return Reply();
    }
    ControlOperationStatus? OperationState(Guid id){lock(operationGate)return operations.GetValueOrDefault(id)?.State;}
    string OperationError(Exception error,Operation? operation=null)=>error is not OperationCanceledException?error.Message:
        operation?.UserCancelled==true?"已按请求取消此操作":disposing.IsCancellationRequested||operation?.ServiceLifetime.IsCancellationRequested==true?"后台正在停止，请稍后重新打开面板":
        operation?.Stop.IsCancellationRequested==true?"操作等待超时，请查看当前状态后重试":"对端或网络请求超时，请检查目标是否在线后重试";
    async Task ServeClient(NamedPipeServerStream pipe,SemaphoreSlim slots,CancellationToken stop){
        using(pipe)using(var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop)){
            timeout.CancelAfter(45000);
            try{var request=await ServiceProtocol.Read<ControlRequest>(pipe,timeout.Token);await ServiceProtocol.Write(pipe,await Handle(request,timeout.Token),timeout.Token);
                byte[] ack=new byte[1];await pipe.ReadAtLeastAsync(ack,1,false,timeout.Token);}
            catch(Exception ex)when(!stop.IsCancellationRequested){Log("控制请求未完成："+ex.GetType().Name+" "+ex.Message);}
            catch(Exception)when(stop.IsCancellationRequested){}
            finally{slots.Release();}
        }
    }
    void DisposeControlResources(){
        if(Interlocked.Exchange(ref disposed,1)!=0)return;
        disposing.Cancel();runStop?.Cancel();measureStop?.Cancel();
        Task[] held;lock(operationGate){held=new[]{running,measuring}.Where(t=>t!=null).Cast<Task>().Concat(operations.Values.Where(o=>!o.Completed).Select(o=>o.Completion.Task)).ToArray();}
        // A timed-out worker retains its single-instance lock. Disposal must not
        // allow a second owner while native/lease references may still be live.
        var finished=Task.WhenAll(held.Select(ObserveShutdown));
        if(finished.IsCompleted){ReleaseControlOwnership();return;}
        _=finished.ContinueWith(_=>ReleaseControlOwnership(),CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
    }
}
