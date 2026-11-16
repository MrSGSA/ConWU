using System.Text.Json;
using System.Security.Cryptography;
using StreamLink.Core;
Console.InputEncoding=new System.Text.UTF8Encoding(false,true);
Console.OutputEncoding=new System.Text.UTF8Encoding(false,true);

// Development-only compatibility oracle. The Rust product never launches it.
var options=new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
MeshLink? link=null;PairKeyExchange? pair=null;
while(await Console.In.ReadLineAsync() is {} line){
 try{
  using var document=JsonDocument.Parse(line);var r=document.RootElement;
  string Text(string k)=>r.GetProperty(k).GetString()!;
  object result=Text("op") switch{
   "link-new"=>NewLink(),
   "hello"=>new{frame=Convert.ToBase64String(link!.Hello())},
   "receive"=>Receive(),
   "data"=>new{frame=Convert.ToBase64String(link!.Data(Convert.FromBase64String(Text("payload")))!)},
   "lane"=>new{frame=Convert.ToBase64String(link!.StreamData(Convert.FromBase64String(Text("payload")),r.GetProperty("lane").GetByte())!)},
   "ping"=>new{frame=Convert.ToBase64String(link!.Ping()!)},
   "identity-fixture"=>Fixture(),
   "tls-fixture"=>TlsFixture(),
   "identity-validate"=>Validate(),
   "pair-new"=>NewPair(),
   "pair-derive"=>Derive(),
   "pair-decrypt"=>new{text=PairKeyExchange.DecryptInvitation(Convert.FromHexString(Text("shared")),Text("cipher"),Text("room"),Text("candidate"),44000)},
   "canonical"=>new{text=JsonSerializer.Serialize(r.GetProperty("value"))},
   "metadata-open"=>OpenMetadata(),
   "metadata-seal"=>SealMetadata(),
   "departure-validate"=>Departure(),
   "pkarr-read"=>Pkarr(),
   "pkarr-state-seal"=>PkarrState(true),
   "pkarr-state-open"=>PkarrState(false),
   "assist-verify"=>Assist(),
   "benchmark"=>Benchmark(),
   "rejoin-create"=>RejoinCreate(),
   "rejoin-resolve"=>RejoinResolve(),
   "traversal-sign"=>TraversalSign(),
   "traversal-verify"=>TraversalVerify(),
   "path-digest"=>new{digest=Convert.ToHexString(PathNomination.ContextDigest(JsonSerializer.Deserialize<TraversalAttemptContext>(r.GetProperty("context").GetRawText())!))},
   _=>throw new InvalidOperationException("Unknown oracle operation")
  };
  Console.WriteLine(JsonSerializer.Serialize(new{ok=true,result},options));
  object NewLink(){link?.Dispose();link=new(r.GetProperty("local").GetInt32(),r.GetProperty("remote").GetInt32(),Convert.FromHexString(Text("shared")));return new{ready=true};}
  object TlsFixture(){using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);var request=new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=ConWU isolated fixture",key,HashAlgorithmName.SHA256);using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(2));return new{pfx=Convert.ToBase64String(certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx)),pin=Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()))};}
  object Receive(){var result=link!.Receive(Convert.FromBase64String(Text("frame")),true);return new{result.Authenticated,reply=result.Reply==null?null:Convert.ToBase64String(result.Reply),packet=result.Packet==null?null:Convert.ToBase64String(result.Packet),link.Connected};}
  object Fixture(){var owner=MeshIdentity.Create("","","tcp",direct:true,pairwise:true);var enrollment=MeshIdentity.Issue(owner);var guest=MeshIdentity.Import(MeshIdentity.Export(enrollment));return new{owner=JsonSerializer.SerializeToElement(owner),guest=JsonSerializer.SerializeToElement(guest),shared=Convert.ToHexString(MeshIdentity.SharedKey(owner,guest.Self)),enrollment=MeshIdentity.Export(enrollment)};}
  object Validate(){var profile=JsonSerializer.Deserialize<MeshProfile>(r.GetProperty("profile").GetRawText())!;profile.Validate();var peer=profile.Directory!.Members.FirstOrDefault(m=>m.Slot!=profile.Self.Slot);return new{profile.Pair.Network,profile.LocalIp,shared=peer==null?"":Convert.ToHexString(MeshIdentity.SharedKey(profile,peer))};}
  object NewPair(){pair?.Dispose();pair=new();return new{pair.PublicKey,pair.Commitment};}
  object Derive(){var shared=pair!.Derive(Text("publicKey"),Text("commitment"),Text("room"),Text("candidate"),r.GetProperty("owner").GetBoolean());try{return new{shared=Convert.ToHexString(shared),sas=PairKeyExchange.Verification(shared),cipher=PairKeyExchange.EncryptInvitation(shared,"oracle approval",Text("room"),Text("candidate"))};}finally{CryptographicOperations.ZeroMemory(shared);}}
  MeshProfile Profile()=>JsonSerializer.Deserialize<MeshProfile>(r.GetProperty("profile").GetRawText())!;
  object RejoinCreate(){pair??=new();var proof=MeshRejoin.Create(MeshRejoin.Retain(Profile()),Text("code"),pair)!;return new{proof=JsonSerializer.SerializeToElement(proof),pair.Commitment,digest=MeshRejoin.Fingerprint(proof)};}
  object RejoinResolve(){var member=MeshRejoin.Resolve(Profile(),JsonSerializer.Deserialize<MeshRejoinProof>(r.GetProperty("proof").GetRawText()),Text("code"),Text("commitment"));return new{member=JsonSerializer.SerializeToElement(member)};}
  object TraversalSign()=>JsonSerializer.SerializeToElement(MeshTraversal.Sign(Profile(),JsonSerializer.Deserialize<MeshTraversalMessage>(r.GetProperty("message").GetRawText())!));
  object TraversalVerify(){var p=Profile();var m=JsonSerializer.Deserialize<MeshTraversalMessage>(r.GetProperty("message").GetRawText())!;MeshTraversal.Verify(p.Pair.Network,p.Directory!.Members.Single(x=>x.Slot==m.FromSlot),p.Directory.Members.Single(x=>x.Slot==m.ToSlot),m);return new{valid=true,fingerprint=Convert.ToHexString(MeshTraversal.Fingerprint(p.Pair.Network,m))};}
  object OpenMetadata(){var p=Profile();var envelope=JsonSerializer.Deserialize<MeshEnvelope>(r.GetProperty("envelope").GetRawText())!;return JsonSerializer.SerializeToElement(MeshMetadata.Open(p,p.Directory!.Members.Single(m=>m.Slot==envelope.Slot),envelope));}
  object SealMetadata(){var p=Profile();var node=JsonSerializer.Deserialize<MeshAnnouncement>(r.GetProperty("announcement").GetRawText())!;return JsonSerializer.SerializeToElement(MeshMetadata.Seal(p,node));}
  object Departure(){var notice=JsonSerializer.Deserialize<NetworkDeparture>(r.GetProperty("notice").GetRawText())!;notice.Validate(Text("owner"));return new{valid=true};}
  object Pkarr(){var record=PkarrPacket.Read(Text("key"),Convert.FromBase64String(Text("wire")),DateTimeOffset.UtcNow);return JsonSerializer.SerializeToElement(record.Announcement);}
  object PkarrState(bool seal){var p=Profile();var peer=p.Directory!.Members.Single(m=>m.Slot!=p.Self.Slot);var record=JsonSerializer.Deserialize<PkarrAnnouncement>(r.GetProperty("announcement").GetRawText())!;if(seal){var state=JsonSerializer.Deserialize<PkarrPeerState>(r.GetProperty("state").GetRawText())!;return new{cipher=PkarrRendezvous.Seal(p,peer,Text("source"),record,state)};}return JsonSerializer.SerializeToElement(PkarrRendezvous.Open(p,peer,Text("source"),record));}
  object Assist(){var p=Profile();var request=JsonSerializer.Deserialize<MimicAssistRequest>(r.GetProperty("request").GetRawText())!;PunchAssistProtocol.Verify(p.Pair.Network,p.Self,request);return new{valid=true};}
  object Benchmark(){byte[] secret=RandomNumberGenerator.GetBytes(32);using var a=new MeshLink(1,2,secret);using var b=new MeshLink(2,1,secret);var ack=b.Receive(a.Hello()).Reply!;var finish=a.Receive(ack).Reply!;b.Receive(finish);byte[] payload=new byte[1280];for(int i=0;i<2000;i++)b.Receive(a.Data(payload)!);int count=r.GetProperty("count").GetInt32();var clock=System.Diagnostics.Stopwatch.StartNew();long bytes=0;for(int i=0;i<count;i++)bytes+=b.Receive(a.Data(payload)!).Packet!.Length;clock.Stop();return new{packets=count,bytes,seconds=clock.Elapsed.TotalSeconds,mbps=bytes*8/clock.Elapsed.TotalSeconds/1_000_000};}
 }catch(Exception error){Console.WriteLine(JsonSerializer.Serialize(new{ok=false,error=error.Message},options));}
 await Console.Out.FlushAsync();
}
link?.Dispose();pair?.Dispose();
