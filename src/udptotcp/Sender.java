package udptotcp;

import javax.management.InvalidAttributeValueException;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class Sender {
    private class SenderTuple<A, B, C, D> {
        private final A successFlag;
        private final B publicKey;
        private final C seq_number;
        private final D ack_number;


        private SenderTuple(A successFlag, B publicKey,C seq_number, D ack_number) {
            this.successFlag = successFlag;
            this.publicKey = publicKey;
            this.seq_number = seq_number;
            this.ack_number = ack_number;
        }


        private A getSuccessFlag() {
            return successFlag;
        }

        private B getPublicKey() {
            return publicKey;
        }

        private C getSeq_number() {
            return seq_number;
        }
        private D getAck_number() {
            return ack_number;
        }
    }



    private long start;
    private byte[] payload;
    private void checkInput(int receiver_port, int MWS, int MSS, int gamma, float pDrop, float pDuplicate,float pCorrupt, float pOrder, int maxOrder, float pDelay, int maxDelay, String filename) throws FileNotFoundException, InvalidAttributeValueException {
        if((receiver_port <= 1024) || (receiver_port>=65536)){
            throw new InvalidAttributeValueException("Port number could not smaller than 1024 and larger than 65536");
        }
        if(MWS < 0){
            throw new InvalidAttributeValueException("MWS size could not be smaller than 0");
        }
        if(MSS < 0){
            throw new InvalidAttributeValueException("MSS size could not be smaller than 0");
        }
        if(gamma < 0){
            throw new InvalidAttributeValueException("Timeout value could not be smaller than 0");
        }
        if((pDrop < 0) || (pDrop >= 1)){
            throw new InvalidAttributeValueException("pDrop value should between 0 and 1");
        }
        if((pDuplicate < 0) || (pDuplicate >= 1)){
            throw new InvalidAttributeValueException("pDuplication value should between 0 and 1");
        }
        if((pCorrupt < 0) || (pCorrupt >= 1)){
            throw new InvalidAttributeValueException("pCorrupt value should between 0 and 1");
        }
        if((pOrder < 0) || (pOrder >= 1)){
            throw new InvalidAttributeValueException("pOrder value should between 0 and 1");
        }
        if((maxOrder < 1) || (maxOrder >6)){
            throw new InvalidAttributeValueException("maxOrder value should between 1 and 6");
        }
        if((pDelay < 0)||(pDelay >= 1)){
            throw new InvalidAttributeValueException("pDelay value should between 0 and 1");
        }
        if(maxDelay < 0){
            throw new InvalidAttributeValueException("maxDelay value shoule be larger than 0");
        }
        File file = new File(filename);
        if(!file.exists()){
            throw new FileNotFoundException("File not found");
        }
    }

    private SenderTuple<Boolean, PublicKey, Integer, Integer> threeWayHandshake(InetAddress receiver_address, int receiver_port, KeyPair keyPair, DatagramSocket datagramSocket, BufferedWriter out) throws Exception{
        STPPacket sendpacket = new STPPacket(1,0,0,0,0,
                new Security().encryptByPrivateKey(keyPair.getPublic().getEncoded(), keyPair.getPrivate()),0,keyPair.getPublic());
        sendpacket.setChecksum(sendpacket.hashCode());
        start = System.currentTimeMillis();
        new SocketManager().send(sendpacket, receiver_address, receiver_port, datagramSocket);
        out.write(String.format("%s %.2f %s %d %d %d\n",
                "snd",((float)(System.currentTimeMillis()-start))/1000,"S",sendpacket.getSeq_number(),sendpacket.getLengthofdata(),sendpacket.getAck_number()));
        DatagramPacket receivepacket = new SocketManager().receive(datagramSocket);
        STPPacket receivestppacket = new STPPacket().toObject(receivepacket);
        out.write(String.format("%s %.2f %s %d %d %d\n",
                "rcv",((float)(System.currentTimeMillis()-start))/1000,"SA",receivestppacket.getSeq_number(),receivestppacket.getLengthofdata(),receivestppacket.getAck_number()));
        payload =  new Security().decryptByPublicKey(receivestppacket.getPayload(),receivestppacket.getPublicKey());
        if(Arrays.equals(payload, receivestppacket.getPublicKey().getEncoded()) && receivestppacket.getAck_bit() == 1 && receivestppacket.getSyn_bit() == 1){
            sendpacket = new STPPacket(1,1,0,receivestppacket.getAck_number(), receivestppacket.getSeq_number()+1,
                    new Security().encryptByPublicKey(keyPair.getPublic().getEncoded(), receivestppacket.getPublicKey()),0,keyPair.getPublic());
            sendpacket.setChecksum(sendpacket.hashCode());
            new SocketManager().send(sendpacket, receiver_address, receiver_port, datagramSocket);
            out.write(String.format("%s %.2f %s %d %d %d\n",
                    "snd",((float)(System.currentTimeMillis()-start))/1000,"A",sendpacket.getSeq_number(),sendpacket.getLengthofdata(),sendpacket.getAck_number()));
            SenderTuple<Boolean, PublicKey, Integer, Integer> result = new SenderTuple<Boolean, PublicKey, Integer, Integer>
                    (true, receivestppacket.getPublicKey(), sendpacket.getSeq_number(), sendpacket.getAck_number());
            return result;
        }
        else{
            SenderTuple<Boolean, PublicKey, Integer, Integer> result = new SenderTuple<Boolean, PublicKey, Integer, Integer>(false, null, 0 , 0);
            return result;
        }
    }

    public void send(DatagramSocket datagramSocket,FileReader fileReader, int MWS, PublicKey receiverPublicKey, int seq_number, int ack_number, InetAddress receiver_address, int receiver_port, BufferedWriter out)throws Exception{
        int position = 0;
        //while(fileReader.readFile(position)!=null){
            byte[] filetrans = fileReader.readFile(position);
            STPPacket sendpacket = new STPPacket(0,0,0,seq_number, ack_number, new Security().encryptByPublicKey(filetrans,receiverPublicKey), filetrans.length);
            new SocketManager().send(sendpacket, receiver_address, receiver_port, datagramSocket);
            out.write(String.format("%s %.2f %s %d %d %d\n",
                    "snd",((float)(System.currentTimeMillis()-start))/1000,"D",sendpacket.getSeq_number(),sendpacket.getLengthofdata(),sendpacket.getAck_number()));
            //position += sendpacket.getLengthofdata();
            DatagramPacket receivepacket = new SocketManager().receive(datagramSocket);
            STPPacket receivestppacket = new STPPacket().toObject(receivepacket);
            out.write(String.format("%s %.2f %s %d %d %d\n",
                    "rcv",((float)(System.currentTimeMillis()-start))/1000,"A",receivestppacket.getSeq_number(),receivestppacket.getLengthofdata(),receivestppacket.getAck_number()));
            //seq_number = receivestppacket.getAck_number();
            //ack_number = receivestppacket.getSeq_number()+receivestppacket.getLengthofdata();
        //}
        out.close();
    }

    public static void main(String args[])throws Exception{
        InetAddress receiver_address = InetAddress.getByName(args[0]);
        int receiver_port = Integer.parseInt(args[1]);
        String filename = args[2];
        int MWS = Integer.parseInt(args[3]);
        int MSS = Integer.parseInt(args[4]);
        int gamma = Integer.parseInt(args[5]);
        float pDrop = Float.parseFloat(args[6]);
        float pDuplicate = Float.parseFloat(args[7]);
        float pCorrupt = Float.parseFloat(args[8]);
        float pOrder = Float.parseFloat(args[9]);
        int maxOrder = Integer.parseInt(args[10]);
        float pDelay = Float.parseFloat(args[11]);
        int maxDelay = Integer.parseInt(args[12]);
        int seed = Integer.parseInt(args[13]);
        Sender sender =  new Sender();
        sender.checkInput(receiver_port, MWS, MSS, gamma, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, filename);
        KeyPair keyPair = new Security().genKeyPair(1024);
        DatagramSocket datagramSocket = new DatagramSocket();
        BufferedWriter out = new FileWriterOut().senderOpenWritingFile();
        SenderTuple<Boolean, PublicKey, Integer, Integer> result= sender.threeWayHandshake(receiver_address, receiver_port, keyPair, datagramSocket,out);
        if(result.getSuccessFlag()){
            FileReader fileReader = new FileReader(filename, MSS);
            sender.send(datagramSocket, fileReader, MWS, result.getPublicKey(), result.getSeq_number(), result.getAck_number(), receiver_address, receiver_port, out);

        }
    }
}
