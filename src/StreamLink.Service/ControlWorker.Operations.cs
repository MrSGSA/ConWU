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
    }
    readonly object operationGate=new();
    readonly Dictionary<Guid,Operation> operations=new();
    readonly CancellationTokenSource disposing=new();
    ControlOperationStatus? operationStatus;
    int disposed;
    Operation OpenOperation(ControlRequest request,CancellationToken token,out bool duplicate)
    {
        lock(operationGate){
            duplicate=false;
            token.ThrowIfCancellationRequested();disposing.Token.ThrowIfCancellationRequested();
            Guid id=request.OperationId==Guid.Empty?Guid.NewGuid():request.OperationId;
            string digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(request)));
            if(operations.TryGetValue(id,out var prior)){
                if(prior.Command!=request.Command||prior.Digest!=digest)throw new IOException("操作ID已被不同请求使用");
                duplicate=true;return prior; // Read progress, never repeat mutation.
            }
            if(operations.Values.Count(o=>!o.Completed)>=8)throw new IOException("已有太多控制操作，稍后重试");
            if(operations.Count>=64){var old=operations.Values.FirstOrDefault(o=>o.Completed);if(old!=null)operations.Remove(old.Id);}
            var entry=new Operation(id,request.Command,digest,CancellationTokenSource.CreateLinkedTokenSource(token,disposing.Token));
            operations.Add(id,entry);Volatile.Write(ref operationStatus,new(id,request.Command,"排队",false,true));PublishReply();return entry;
        }
    }
    void SetOperation(Operation operation,string phase,bool cancelable){lock(operationGate){operation.Cancelable=cancelable;operation.State=new(operation.Id,operation.Command,phase,false,cancelable);Volatile.Write(ref operationStatus,operation.State);}PublishReply();}
    void CompleteOperation(Operation operation,string error=""){
        lock(operationGate){if(operation.Completed)return;operation.Completed=true;operation.Cancelable=false;operation.Stop.Dispose();
            operation.State=new(operation.Id,operation.Command,error.Length==0?"已完成":"未完成",true,false,error);
            if(operationStatus?.Id==operation.Id)Volatile.Write(ref operationStatus,operation.State);operation.Completion.TrySetResult();}
    }
    ControlReply CancelOperation(Guid id){
        lock(operationGate){if(id==Guid.Empty||!operations.TryGetValue(id,out var op)||op.Completed)return Reply("未找到运行中的操作");
            if(!op.Cancelable)return Reply("操作已进入资源退出阶段，可取消界面等待，但不能撤销已请求的网络停止");op.Stop.Cancel();}
        return Reply();
    }
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
        if(finished.IsCompleted){lease.Dispose();return;}
        _=finished.ContinueWith(_=>lease.Dispose(),CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
    }
}
