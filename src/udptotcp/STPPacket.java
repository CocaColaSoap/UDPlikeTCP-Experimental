package udptotcp;

import java.io.*;
import java.net.DatagramPacket;
import java.security.PublicKey;

public class STPPacket implements Serializable {

    public int syn_bit;
    public int ack_bit;
    public int fin_bit;
    public int seq_number;
    public int ack_number;
    public byte[] payload;
    public int lengthofdata;
    public PublicKey publicKey ;
    public int checksum;
    public STPPacket(){}

    public STPPacket(int syn_bit, int ack_bit, int fin_bit, int seq_number, int ack_number, byte[] payload, int lengthofdata, PublicKey publicKey){
        this.syn_bit = syn_bit;
        this.ack_bit = ack_bit;
        this.fin_bit = fin_bit;
        this.seq_number = seq_number;
        this.ack_number = ack_number;
        this.payload = payload;
        this.lengthofdata = lengthofdata;
        this.publicKey = publicKey;
    }

    public STPPacket(int syn_bit, int ack_bit, int fin_bit, int seq_number, int ack_number, byte[] payload, int lengthofdata){
        this.syn_bit = syn_bit;
        this.ack_bit = ack_bit;
        this.fin_bit = fin_bit;
        this.seq_number = seq_number;
        this.ack_number = ack_number;
        this.payload = payload;
        this.lengthofdata = lengthofdata;
    }



    public int getSyn_bit() {
        return syn_bit;
    }

    public void setSyn_bit(int syn_bit) {
        this.syn_bit = syn_bit;
    }

    public int getAck_bit() {
        return ack_bit;
    }

    public void setAck_bit(int ack_bit) {
        this.ack_bit = ack_bit;
    }

    public int getFin_bit() {
        return fin_bit;
    }

    public void setFin_bit(int fin_bit) {
        this.fin_bit = fin_bit;
    }

    public int getSeq_number() {
        return seq_number;
    }

    public void setSeq_number(int seq_number) {
        this.seq_number = seq_number;
    }

    public int getAck_number() {
        return ack_number;
    }

    public void setAck_number(int ack_number) {
        this.ack_number = ack_number;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    public int getLengthofdata() {
        return lengthofdata;
    }

    public void setLengthofdata(int lengthofdata) {
        this.lengthofdata = lengthofdata;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public int getChecksum() {
        return checksum;
    }

    public void setChecksum(int checksum) {
        this.checksum = checksum;
    }



    public STPPacket toObject(DatagramPacket datagramPacket) throws Exception{
        ByteArrayInputStream bin=new ByteArrayInputStream(datagramPacket.getData());
        ObjectInputStream ois=new ObjectInputStream(bin);
        STPPacket receivepacket = (STPPacket) ois.readObject();
        bin.close();
        ois.close();
        return receivepacket;
    }

    public byte[] toBytesArray(STPPacket sendpacket)throws Exception{
        ByteArrayOutputStream bos=new ByteArrayOutputStream();
        ObjectOutputStream oos=new ObjectOutputStream(bos);
        oos.writeObject(sendpacket);
        byte[] packetArray = bos.toByteArray();
        bos.close();
        oos.close();
        return packetArray;
    }


}
