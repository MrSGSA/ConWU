using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static class ResumableDownloadChecks
{
    public static async Task<int> Run()
    {
        int checks=0;void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS "+name);}
        string root=Path.Combine(Path.GetTempPath(),"conwu-update-download-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        byte[] data=Enumerable.Range(0,16384).Select(n=>(byte)(n*17)).ToArray();
        var package=new ReleaseUpdatePackage("ConWU-2.0.0-x64.msi",ReleaseUpdateClient.Repository+"/releases/download/v2.0.0/ConWU-2.0.0-x64.msi",data.Length,Convert.ToHexString(SHA256.HashData(data)));
        var policy=new UpdateDownloadPolicy(TimeSpan.FromMilliseconds(300),TimeSpan.FromMilliseconds(100),TimeSpan.Zero,2);
        string Target(string name)=>Path.Combine(root,name+".msi");
        async Task Transfer(string name,Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send){
            using var http=new HttpClient(new Handler(send));
            await UpdatePackageTransfer.Download(package,Target(name),(_,_)=>{},default,http,policy);
        }
        int calls=0;
        await Transfer("retry",(request,_)=>{
            calls++;
            if(calls==1)return Task.FromResult(Reply(new CutStream(data,2048),data.Length));
            Check(request.Headers.Range?.Ranges.Single().From==2048,"a dropped connection resumes from the exact saved byte offset");
            return Task.FromResult(Partial(data,2048));
        });
        Check(File.ReadAllBytes(Target("retry")).SequenceEqual(data),"resumed bytes form the one complete hash-verified installer");

        calls=0;var progress=new List<long>();
        using(var http=new HttpClient(new Handler((_,_)=>Task.FromResult(++calls==1?Reply(new CutStream(data,2048),data.Length):Reply(new MemoryStream(data),data.Length)))))
            await UpdatePackageTransfer.Download(package,Target("ignored"),(n,_)=>progress.Add(n),default,http,policy);
        Check(calls==2&&File.ReadAllBytes(Target("ignored")).SequenceEqual(data)&&progress.Contains(2048)&&progress.Last()==data.Length,
            "a server ignoring Range safely restarts the file instead of duplicating its prefix");

        calls=0;
        using(var http=new HttpClient(new Handler((_,_)=>{calls++;return Task.FromResult(Reply(new CutStream(data,2048),data.Length));}))){
            bool stopped=false;try{await UpdatePackageTransfer.Download(package,Target("no-progress"),(_,_)=>{},default,http,policy);}catch(IOException error){stopped=error.Message.Contains("已保留");}
            Check(stopped&&calls==2&&!File.Exists(Target("no-progress")),"repeatedly restarting the same prefix cannot evade the stalled-download retry limit");
        }

        calls=0;int origins=0;
        await Transfer("redirect",(request,_)=>{
            calls++;
            if(request.RequestUri!.Host=="github.com")return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect){Headers={Location=new Uri("https://release-assets.githubusercontent.com/package?sig="+(++origins))}});
            if(origins==1)return Task.FromResult(Reply(new CutStream(data,2048),data.Length));
            Check(request.RequestUri.Query=="?sig=2"&&request.Headers.Range?.Ranges.Single().From==2048,"retry obtains a fresh CDN redirect and preserves its Range request");
            return Task.FromResult(Partial(data,2048));
        });
        Check(origins==2&&calls==4,"temporary signed CDN URLs are refreshed through the canonical release URL");

        string canceled=Target("cancel");
        using(var stop=new CancellationTokenSource())using(var http=new HttpClient(new Handler((_,_)=>Task.FromResult(Reply(new CutStream(data,2048,cancel:stop),data.Length))))){
            bool interrupted=false;try{await UpdatePackageTransfer.Download(package,canceled,(_,_)=>{},stop.Token,http,policy);}catch(OperationCanceledException){interrupted=true;}
            Check(interrupted&&!File.Exists(canceled)&&new FileInfo(canceled+".partial").Length==2048,"caller cancellation keeps a non-installable partial file for a later retry");
            var binding=JsonDocument.Parse(File.ReadAllText(canceled+".partial.json"));
            Check(binding.RootElement.GetProperty("Url").GetString()==package.Url,"durable resume metadata binds the canonical URL without a signed CDN token");
        }
        using(var http=new HttpClient(new Handler((request,_)=>{
            Check(request.Headers.Range?.Ranges.Single().From==2048,"a new downloader invocation restores the saved prefix");return Task.FromResult(Partial(data,2048));
        })))await UpdatePackageTransfer.Download(package,canceled,(_,_)=>{},default,http,policy);
        Check(File.ReadAllBytes(canceled).SequenceEqual(data)&&!File.Exists(canceled+".partial.json"),"successful verification removes transfer metadata and promotes the complete package");

        calls=0;
        await Transfer("stall",(_,_)=>Task.FromResult(++calls==1?Reply(new CutStream(data,2048,stall:true),data.Length):Partial(data,2048)));
        Check(calls==2&&File.Exists(Target("stall")),"a stalled body is timed out and retried without discarding its prefix");
        var watch=Stopwatch.StartNew();
        using(var http=new HttpClient(new Handler((_,_)=>Task.FromResult(Reply(new CutStream(data,data.Length,slow:true),data.Length)))))
            await UpdatePackageTransfer.Download(package,Target("slow"),(_,_)=>{},default,http,policy);
        Check(watch.Elapsed>policy.HeaderTimeout&&File.Exists(Target("slow")),"steady slow progress may outlive request-header and idle budgets without a total-download timeout");

        foreach(bool wrongTotal in new[]{false,true}){
            string name=wrongTotal?"wrong-total":"wrong-offset";calls=0;bool rejected=false;
            using var http=new HttpClient(new Handler((_,_)=>{
                if(++calls==1)return Task.FromResult(Reply(new CutStream(data,2048),data.Length));
                var response=Partial(data,2048);response.Content.Headers.ContentRange=wrongTotal?new ContentRangeHeaderValue(2048,data.Length-1,data.Length+1):new ContentRangeHeaderValue(2049,data.Length-1,data.Length);
                return Task.FromResult(response);
            }));
            try{await UpdatePackageTransfer.Download(package,Target(name),(_,_)=>{},default,http,policy);}catch(IOException){rejected=true;}
            Check(rejected&&!File.Exists(Target(name))&&!File.Exists(Target(name)+".partial"),"invalid resume "+(wrongTotal?"total length":"offset")+" cannot produce an installer");
        }
        calls=0;
        using(var http=new HttpClient(new Handler((_,_)=>Task.FromException<HttpResponseMessage>(new HttpRequestException("offline"))))){
            bool retained=false;try{await UpdatePackageTransfer.Download(package,Target("offline"),(_,_)=>{},default,http,policy);}catch(IOException error){retained=error.Message.Contains("已保留")&&error.Message.Contains("当前网络保持运行");}
            Check(retained&&File.Exists(Target("offline")+".partial")&&!File.Exists(Target("offline")),"exhausted network retries preserve resumable state and expose an actionable message");
        }
        var other=data.Select(b=>(byte)(b^71)).ToArray();string changed=Target("changed");
        using(var stop=new CancellationTokenSource())using(var http=new HttpClient(new Handler((_,_)=>Task.FromResult(Reply(new CutStream(data,2048,cancel:stop),data.Length))))){
            try{await UpdatePackageTransfer.Download(package,changed,(_,_)=>{},stop.Token,http,policy);}catch(OperationCanceledException){}
        }
        using(var http=new HttpClient(new Handler((request,_)=>{
            Check(request.Headers.Range==null,"a different trusted hash never reuses the old package prefix");return Task.FromResult(Reply(new MemoryStream(other),other.Length));
        })))await UpdatePackageTransfer.Download(package with{Sha256=Convert.ToHexString(SHA256.HashData(other))},changed,(_,_)=>{},default,http,policy);
        Check(File.ReadAllBytes(changed).SequenceEqual(other),"resume state is isolated by canonical package identity and digest");
        return checks;
    }
    static HttpResponseMessage Reply(Stream stream,long length)=>new(HttpStatusCode.OK){Content=new StreamContent(stream){Headers={ContentLength=length}}};
    static HttpResponseMessage Partial(byte[] bytes,int offset)=>new(HttpStatusCode.PartialContent){Content=new ByteArrayContent(bytes[offset..]){Headers={ContentRange=new ContentRangeHeaderValue(offset,bytes.Length-1,bytes.Length)}}};
    sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request,token);}
    sealed class CutStream(byte[] data,int cut,bool stall=false,CancellationTokenSource? cancel=null,bool slow=false):Stream
    {
        int offset;
        public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
        public override long Length=>data.Length;public override long Position{get=>offset;set=>throw new NotSupportedException();}
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default){
            token.ThrowIfCancellationRequested();
            if(slow){await Task.Delay(15,token);if(offset==data.Length)return 0;}
            else if(offset>=cut){if(cancel!=null){cancel.Cancel();token.ThrowIfCancellationRequested();}if(stall)await Task.Delay(Timeout.Infinite,token);throw new IOException("fixture connection reset");}
            int count=Math.Min(Math.Min(buffer.Length,slow?512:1024),Math.Min(data.Length-offset,cut-offset));
            data.AsMemory(offset,count).CopyTo(buffer);offset+=count;return count;
        }
        public override int Read(byte[] buffer,int offset,int count)=>throw new NotSupportedException();public override void Flush(){}
        public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
    }
}
