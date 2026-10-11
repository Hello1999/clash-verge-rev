using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
class LocalServicesProbe {
    static int Main(string[] args) {
        try {
            var endpoint = new IPEndPoint(IPAddress.Parse(args[1]), int.Parse(args[2]));
            byte[] payload = Encoding.ASCII.GetBytes("local-service-probe");
            if (args[0] == "tcp") {
                using (var client = new TcpClient(endpoint.AddressFamily)) {
                    if (!client.ConnectAsync(endpoint.Address, endpoint.Port).Wait(3000)) return 3;
                    client.GetStream().Write(payload, 0, payload.Length);
                }
            } else {
                using (var client = new UdpClient(endpoint.AddressFamily)) client.Send(payload, payload.Length, endpoint);
            }
            Console.WriteLine("SENT"); return 0;
        } catch (Exception ex) {
            var root = ex.GetBaseException() as SocketException;
            Console.WriteLine(root == null ? "ERROR" : root.SocketErrorCode.ToString()); return 2;
        }
    }
}
