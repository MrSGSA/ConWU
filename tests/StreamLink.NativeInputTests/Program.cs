using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

if(args.Length!=1)throw new ArgumentException("Provide the corpus produced by the complete native parser test");
int frames=0,accepted=0,rejected=0,mismatches=0;
foreach(string line in File.ReadLines(args[0])){
    bool native=line[0]=='1';byte[] packet=Convert.FromHexString(line[2..]);
    bool managed=TcpCaptureOwner.Tuple(packet,out _,out var target)&&target.Port==41080&&TcpPacketValidation.Checksums(packet);
    frames++;if(native)accepted++;else rejected++;
    if(managed!=native){if(mismatches<10)Console.Error.WriteLine($"classification differs at frame {frames}");mismatches++;}
}
Console.WriteLine(JsonSerializer.Serialize(new{scope="same offline frames through complete native parser and managed TCP admission; not driver/WAN",frames,accepted,rejected,mismatches,corpusSha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(args[0]))),status=mismatches==0?"Pass":"Fail"}));
return mismatches==0?0:1;
