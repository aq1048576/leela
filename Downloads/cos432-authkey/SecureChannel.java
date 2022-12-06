import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

public class SecureChannel extends InsecureChannel {
    // This is just like an InsecureChannel, except that it provides 
    //    authenticated encryption for the messages that pass
    //    over the channel.   It also guarantees that messages are delivered 
    //    on the receiving end in the same order they were sent (returning
    //    null otherwise).  Also, when the channel is first set up,
    //    the client authenticates the server's identity, and the necessary
    //    steps are taken to detect any man-in-the-middle (and to close the
    //    connection if a MITM is detected).
    //
    // The code provided here is not secure --- all it does is pass through
    //    calls to the underlying InsecureChannel.

    // do diffie hellman key exchange
    // do RSAKey exchange
    // 
    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;

    // storing the decryptor and encryptor made with the session key
    private AuthDecryptor decryptor;
    private AuthEncryptor encryptor;
    // the nonce that we maintain for sending messages
    private BigInteger sendNonce;
    // the nonce that we maintain for receiving messages
    private BigInteger recieveNonce;

    public SecureChannel(InputStream inStr, OutputStream outStr,
                         PRGen rand, boolean iAmServer,
                         RSAKey serverKey) throws IOException {
        // if iAmServer==false, then serverKey is the server's *public* key
        // if iAmServer==true, then serverKey is the server's *private* key
        
        super(inStr, outStr);
        // initiate the nonce that we will use to 0
        this.sendNonce = BigInteger.valueOf(0);
        this.recieveNonce = BigInteger.valueOf(0);
        // key exchange for diffie hellman, forward secure generation of a new session key each time a SecureChannel is constructed
        KeyExchange ke = new KeyExchange(rand, iAmServer);
        // verify and set as key
        byte[] out = ke.prepareOutMessage();
        super.sendMessage(out);

        byte[] in = super.receiveMessage();
        byte[] sessionKey = ke.processInMessage(in);
        // set the encryptor and decryptor
        this.decryptor = new AuthDecryptor(sessionKey);
        this.encryptor = new AuthEncryptor(sessionKey);
        
        // send the encrypted message as signed if server
        if (iAmServer){
            byte[] signature = serverKey.sign(sessionKey, rand);
            this.sendMessage(signature);
        }
        // verify the signature of not server
        else{
            byte[] signature = this.receiveMessage();
            boolean valid = serverKey.verifySignature(sessionKey, signature);
            if (!valid){
                // set the session key to null so past messages cannot be recovered, since the man in the middle might
                // be able to see things
                sessionKey = null;
                // close the channel
                super.close();
            }
        }

    
    }
   
    public void sendMessage(byte[] message) throws IOException {
        // convert the nonce to a byte array
        byte[] nonce = HW2Util.bigIntegerToBytes(sendNonce, NONCE_SIZE_BYTES);
        // increment the nonce
        sendNonce = sendNonce.add(BigInteger.valueOf(1));
        // encrypt the message, put in the nonce so we can check if it is correct
        byte[] output = encryptor.authEncrypt(message, nonce, true);
        // send the encrypted message
        super.sendMessage(output);    
    }

    public byte[] receiveMessage() throws IOException {
        // receive the encrypted message
        byte[] input = super.receiveMessage();  
        // convert nonce into byte array
        byte[] nonce = HW2Util.bigIntegerToBytes(recieveNonce, NONCE_SIZE_BYTES);
        // increment your nonce
        recieveNonce = recieveNonce.add(BigInteger.valueOf(1));

        // split up the input into input and nonce
        int inLength = input.length-NONCE_SIZE_BYTES;

        // sanity check on the length of our input
        if (inLength<0 ){
            return null;
        }

        byte[] newIn = new byte[inLength];

        byte[] nonceCheck = new byte[NONCE_SIZE_BYTES];

        for (int i = 0; i<inLength; i++){
           newIn[i] = input[i];
        }

        for (int i = 0; i<NONCE_SIZE_BYTES; i++){
         nonceCheck[i] = input[i+inLength];
        }
        // check if each entry is the same
        for (int i = 0; i<NONCE_SIZE_BYTES; i++){
            if (nonceCheck[i] != nonce[i]) {
                // return null if not
                return null;
            }
        }
        // return the decrypted input
        return decryptor.authDecrypt(input);
    }
    public static void main(String[] args){
    // SecureChannel sc = new SecureChannel(inStr, outStr, rand, iAmServer, serverKey)
    }
}
