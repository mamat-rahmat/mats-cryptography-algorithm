/**
 * Created by ramandika on 21/03/16.
 * Block bytes dengan ukuran 128 bit plain teks, cipher, dan key
 */
public class BlockBtyes {
    private byte[] bytes;

    public BlockBtyes(byte[] input){
        bytes=new byte[16];

    }
    public void setByte(int pos, byte val){
        bytes[pos]=val;
    }
    public byte getByte(int pos){
        return bytes[pos];
    }

}
