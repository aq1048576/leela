/**********************************************************************************/
/* AuthDecrytor.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated decryption of data encrypted using         */
/*              AuthEncryptor.java.                                               */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Decrypt data encrypted by your implementation of AuthEncryptor.java */
/*            if provided with the appropriate key and nonce.  If the data has    */
/*            been tampered with, return null.                                    */
/*                                                                                */
/**********************************************************************************/

public class AuthDecryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;
    public static final int MAC_SIZE_BYTES = AuthEncryptor.MAC_SIZE_BYTES;

    // Instance variables.
    // IMPLEMENT THIS
    // storing the keys for the decryption
    private final byte[] encryptKey;
    private final byte[] macKey;

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        // same process as encryption
        PRGen seeder = new PRGen(key);
        this.encryptKey = new byte[KEY_SIZE_BYTES];
        this.macKey = new byte[KEY_SIZE_BYTES];
        seeder.nextBytes(this.encryptKey);
        seeder.nextBytes(this.macKey);
        
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce has been included in <in>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in) {
       // System.out.printf("dec w nonce: inlength %d", in.length);
       // System.out.printf("dec w nonce: noncelength %d", nonce.length);
        int inLength = in.length-NONCE_SIZE_BYTES;
        if (inLength<0 ){
            return null;
        }
        // array.copyof(range) splitting up the nonce from the encrypted message and mac
        byte[] newIn = new byte[inLength];
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        for (int i = 0; i<inLength; i++){
           newIn[i] = in[i];
        }
        for (int i = 0; i<NONCE_SIZE_BYTES; i++){
         nonce[i] = in[i+inLength];
        }
        byte[] returned = authDecrypt(newIn, nonce);
        return returned;
        
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce used to encrypt the data is provided in <nonce>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in, byte[] nonce) {
       //System.out.printf("dec: inlength %d", in.length);
       // System.out.printf("dec: noncelength %d", nonce.length);
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;
        int messageLength = in.length-MAC_SIZE_BYTES;
        if (messageLength<0 ){
            return null;
        }
        // decrypt in the same way we encrypt

        byte[] enc = new byte[messageLength];
        byte[] mac = new byte[MAC_SIZE_BYTES];
        byte[] macinput = new byte[messageLength+NONCE_SIZE_BYTES];

        for (int i = 0; i<messageLength; i++){
            enc[i] = in[i];
        }
        for (int i = 0; i<MAC_SIZE_BYTES; i++){
            mac[i] = in[i+messageLength];
        }
        for (int i = 0; i<messageLength; i++){
            macinput[i] = in[i];
        }
        for (int i = 0; i<NONCE_SIZE_BYTES; i++){
            macinput[i+messageLength] = nonce[i];
        }

        byte[] output = new byte[messageLength];


        StreamCipher sc = new StreamCipher(encryptKey, nonce);
        sc.cryptBytes(enc, 0, output, 0, messageLength);
    
        PRF prf = new PRF(macKey);
        byte[] macCheck = prf.eval(macinput);
        // redundant but is good coding sanity check
        if (macCheck.length != mac.length) return null;
        // check that the macs are equal to the expected
        for (int i = 0; i<MAC_SIZE_BYTES; i++){
            if (macCheck[i]!= mac[i]){
                return null;
            }
        }
        return output;
    }
    public static void main(String[] args){
        byte[] bytes = {50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4};
        byte[] bytes1 = {50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2,
             3, 4,50,0, 0, 0, 0, 0, 0, 0, 0};
        byte[] bytes2 = {0, 0, 0, 0, 0, 0, 0, 0};
        AuthEncryptor enc = new AuthEncryptor(bytes);
        byte[] enc1 = enc.authEncrypt(bytes, bytes2, true);
        byte[] enc2 = enc.authEncrypt(bytes, bytes2, false);
        AuthDecryptor dec = new AuthDecryptor(bytes);
       byte[] first = dec.authDecrypt(enc1);
       System.out.print(first == null);
        byte[] second = dec.authDecrypt(enc2, bytes2);
        for (int i = 0; i< first.length; i++){
           System.out.printf("%dth one: %d \n", i, first[i]);
        }
       for (int i = 0; i< second.length; i++){
            System.out.printf("%dth one: %d \n", i, second[i]);
       }

        
        
    }
}
