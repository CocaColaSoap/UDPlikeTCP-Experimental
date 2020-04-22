package udptotcp;

import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class SocketManager {

    public void send(STPPacket sendpacket, InetAddress receiver_address, int receiver_port, DatagramSocket datagramSocket)throws Exception{
        byte[] packetArray = new STPPacket().toBytesArray(sendpacket);
        DatagramPacket datagramPacket = new DatagramPacket(packetArray, packetArray.length, receiver_address, receiver_port);
        datagramSocket.send(datagramPacket);
    }


    public DatagramPacket receive(DatagramSocket datagramSocket)throws Exception{
            byte[] data = new byte[1024];
            DatagramPacket datagramPacket = new DatagramPacket(data, data.length);
            datagramSocket.receive(datagramPacket);
            return datagramPacket;
    }
}
