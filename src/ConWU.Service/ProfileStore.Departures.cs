namespace StreamLink.Service;

public sealed partial class ProfileStore
{
    internal ProfileStore DeviceStore=>deviceStore?.DeviceStore??this;
    internal event Action? DepartureQueued;
    internal NetworkDepartureDelivery[] ReadDepartures(){var root=DeviceStore;lock(root.persistenceGate)return root.ReadPrivate<NetworkDepartureDelivery[]>("pending-departures.dat")??[];}
    internal void QueueDeparture(NetworkDepartureDelivery item)
    {
        var root=DeviceStore;
        lock(root.persistenceGate){
            var current=root.ReadDepartures();if(current.Any(n=>n.Notice.Nonce==item.Notice.Nonce))return;
            if(current.Length>=256)throw new IOException("待通知主机的退出记录已满，请保留网络并稍后重试");
            root.WritePrivate("pending-departures.dat",current.Append(item).ToArray());
        }
        root.DepartureQueued?.Invoke();
    }
    internal void CompleteDeparture(string nonce)
    {
        var root=DeviceStore;lock(root.persistenceGate){var current=root.ReadDepartures();var next=current.Where(n=>n.Notice.Nonce!=nonce).ToArray();if(next.Length!=current.Length){if(next.Length>0)root.WritePrivate("pending-departures.dat",next);else root.DeletePrivate("pending-departures.dat");}}
    }
}
