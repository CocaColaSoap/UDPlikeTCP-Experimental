package udptotcp;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class Receiver {
    private class ReceiverTuple<A, B>{
        private final A successFlag;
        private final B publicKey;

        private ReceiverTuple(A successFlag, B publicKey) {
            this.successFlag = successFlag;
            this.publicKey = publicKey;
        }

        public A getSuccessFlag() {
            return successFlag;
        }

        public B getPublicKey() {
            return publicKey;
        }

    }

    private long start;
    private byte[] payload;
    public ReceiverTuple<Boolean, PublicKey> threeWayHandShake(DatagramSocket datagramSocket, KeyPair keyPair, BufferedWriter out)throws Exception{
        DatagramPacket receivepacket = new SocketManager().receive(datagramSocket);
        STPPacket receivestppacket = new STPPacket().toObject(receivepacket);
        start = System.currentTimeMillis();
        out.write(String.format("%s %.2f %s %d %d %d\n",
                "rcv",((float)(System.currentTimeMillis()-start))/1000,"S",receivestppacket.getSeq_number(),receivestppacket.getLengthofdata(),receivestppacket.getAck_number()));
        payload = new Security().decryptByPublicKey(receivestppacket.getPayload(),receivestppacket.getPublicKey());
        if(Arrays.equals(payload, receivestppacket.getPublicKey().getEncoded()) && receivestppacket.getSyn_bit() == 1){
            STPPacket sendpacket = new STPPacket(1,1,0,0,receivestppacket.getSeq_number()+1,
                    new Security().encryptByPrivateKey(keyPair.getPublic().getEncoded(),keyPair.getPrivate()),0,keyPair.getPublic());
            new SocketManager().send(sendpacket, receivepacket.getAddress(), receivepacket.getPort(), datagramSocket);
            out.write(String.format("%s %.2f %s %d %d %d\n",
                    "snd",((float)(System.currentTimeMillis()-start))/1000,"SA",sendpacket.getSeq_number(),sendpacket.getLengthofdata(),sendpacket.getAck_number()));
            receivepacket = new SocketManager().receive(datagramSocket);
            receivestppacket = new STPPacket().toObject(receivepacket);
            out.write(String.format("%s %.2f %s %d %d %d\n",
                    "rcv",((float)(System.currentTimeMillis()-start))/1000,"A",receivestppacket.getSeq_number(),receivestppacket.getLengthofdata(),receivestppacket.getAck_number()));
            payload = new Security().decryptByPrivateKey(receivestppacket.getPayload(),keyPair.getPrivate());
            if(Arrays.equals(payload, receivestppacket.getPublicKey().getEncoded()) && receivestppacket.getSyn_bit() == 1 && receivestppacket.getAck_bit() == 1){
                ReceiverTuple<Boolean, PublicKey> result = new ReceiverTuple<>
                        (true, receivestppacket.getPublicKey());
                return result;
            }
            else{
                ReceiverTuple<Boolean, PublicKey> result = new ReceiverTuple<>
                        (false, null);
                return result;
            }

        }else{
            ReceiverTuple<Boolean, PublicKey> result = new ReceiverTuple<>
                    (false, null);
            return result;
        }

    }

    public void Receive(DatagramSocket datagramSocket, BufferedWriter out, PublicKey publicKey, String filename, KeyPair keyPair)throws Exception{
        FileOutputStream out_file = new FileOutputStream(filename);
        while(true){
            DatagramPacket receivepacket = new SocketManager().receive(datagramSocket);
            STPPacket receivestppacket = new STPPacket().toObject(receivepacket);
            if(receivestppacket.getFin_bit() == 1) {
                break;
            }
            out.write(String.format("%s %.2f %s %d %d %d\n",
                    "rcv",((float)(System.currentTimeMillis()-start))/1000,"D",receivestppacket.getSeq_number(),receivestppacket.getLengthofdata(),receivestppacket.getAck_number()));
            STPPacket sendpacket = new STPPacket(0,0,0,receivestppacket.getAck_number(), receivestppacket.getSeq_number()+receivestppacket.getLengthofdata(),null,0);
            out_file.write(new Security().decryptByPrivateKey(receivestppacket.getPayload(), keyPair.getPrivate()));
            new SocketManager().send(sendpacket, receivepacket.getAddress(), receivepacket.getPort(), datagramSocket);
            out.write(String.format("%s %.2f %s %d %d %d\n",
                    "snd",((float)(System.currentTimeMillis()-start))/1000,"SA",sendpacket.getSeq_number(),sendpacket.getLengthofdata(),sendpacket.getAck_number()));
        }
        out_file.close();
        out.close();

    }
    public static void main(String args[])throws Exception{
        int receiver_port = Integer.parseInt(args[0]);
        String file_name = args[1];
        KeyPair keyPair = new Security().genKeyPair(1024);
        DatagramSocket datagramSocket = new DatagramSocket(receiver_port, InetAddress.getByName("127.0.0.1"));
        Receiver receiver = new Receiver();
        BufferedWriter out = new FileWriterOut().receiverOpenWritingFile();
        ReceiverTuple<Boolean, PublicKey> result = receiver.threeWayHandShake(datagramSocket,keyPair,out);
        if(result.getSuccessFlag()){
            receiver.Receive(datagramSocket, out, result.getPublicKey(), file_name, keyPair);
            //out.close();
        }
    }
}
