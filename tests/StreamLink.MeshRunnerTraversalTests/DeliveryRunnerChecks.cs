using System.Diagnostics;
using StreamLink.Core;

static class DeliveryRunnerChecks
{
    public static async Task<object> Run(SessionStatus?[] states,bool expected,string mode,Action<bool,string> check,CancellationToken token)
    {
        var clock=Stopwatch.StartNew();
        if(expected){
            while(!states.All(s=>s?.Peers?.Single().Delivery?.Reports.Length>0)){
                if(clock.ElapsedMilliseconds>7000)throw new Exception("formal delivery feedback did not arrive: "+mode);
                await Task.Delay(10,token);
            }
            check(states.All(s=>s!.Peers!.Single().Delivery!.Reports.Single() is {AcceptedPackets:1,AcceptedBytes:1280,PeerDeliveredPackets:1,PeerDeliveredBytes:1280,Result:"ReportedAtCutoff"}),
                mode+": bilateral/server-negotiated formal Runner records real encrypted same-path receipt for both complete IP packets");
        }else{
            await Task.Delay(3200,token);
            check(states.All(s=>s!.Peers!.Single().Delivery==null),mode+": missing peer/server capability prevents history allocation and delivery queries on a healthy path");
        }
        check(states.All(s=>s!.Connected&&s.Peers!.Single().Traffic!.Qualification=="QualityUnknown"),mode+": authenticated receipt does not replace qualification or policy");
        return new{mode,expected,delivery=states.Select(s=>s!.Peers!.Single().Delivery).ToArray()};
    }
}
