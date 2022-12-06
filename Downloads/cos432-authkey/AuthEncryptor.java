/**********************************************************************************/
/* AuthEncryptor.java                                                             */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated encryption of data.                        */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement authenticated encryption, ensuring:                       */
/*            (1) Confidentiality: the only way to recover encrypted data is to   */
/*                perform authenticated decryption with the same key and nonce    */
/*                used to encrypt the data.                                       */
/*            (2) Integrity: A party decrypting the data using the same key and   */
/*                nonce that were used to encrypt it can verify that the data has */
/*                not been modified since it was encrypted.                       */
/*                                                                                */
/**********************************************************************************/
public class AuthEncryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;
    public static final int MAC_SIZE_BYTES = PRF.OUTPUT_SIZE_BYTES;
    public static final int RSA_BYTES = 200;

   
    // encryption key, is constant across a session
    private final byte[] encryptKey;
    // mac key, is constant across a session
    private final byte[] macKey;

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

         // this ensures that the keys for the encryption and mac are distinct and cannot be recovered from each other, since
        // the prg provides forward secrecy
        PRGen seeder = new PRGen(key);
        this.encryptKey = new byte[KEY_SIZE_BYTES];
        this.macKey = new byte[KEY_SIZE_BYTES];
        seeder.nextBytes(encryptKey);
        seeder.nextBytes(macKey);
       
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are protected against those who do not
    //     know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the output.
    // Returns a newly allocated byte[] containing the authenticated encryption of the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        // make a StreamCipher for encryption
        StreamCipher sc = new StreamCipher(encryptKey, nonce);

        int inLength = in.length;

        byte[] enc = new byte[inLength];
        // encryption of message
        sc.cryptBytes(in, 0, enc, 0, inLength);

        byte[] macinput = new byte[inLength+NONCE_SIZE_BYTES];

        // for loops because i didn't know copy array existed, mac input includes the encrypted array and the nonce
        for (int i = 0; i<inLength; i++){
            macinput[i] = enc[i];
        }
        for (int i = 0; i<NONCE_SIZE_BYTES; i++){
            macinput[i+inLength] = nonce[i];
        }
        // construct the mac
        PRF prf = new PRF(macKey);
        byte[] mac = prf.eval(macinput);
        // append the mac to the encrypted message
        if (!includeNonce){
            byte[] output = new byte[inLength+MAC_SIZE_BYTES];
            for (int i = 0; i<inLength; i++){
                output[i] = enc[i];
            }
            for (int i = 0; i<MAC_SIZE_BYTES; i++){
                output[i+inLength] = mac[i];
            }
            return output;
        }
        // append the nonce
        else{
            byte[] output = new byte[inLength+MAC_SIZE_BYTES+NONCE_SIZE_BYTES];
            for (int i = 0; i<inLength; i++){
                output[i] = enc[i];
            }
            for (int i = 0; i<MAC_SIZE_BYTES; i++){
                output[i+inLength] = mac[i];
            }
            for (int i = 0; i<NONCE_SIZE_BYTES; i++){
                output[i+inLength+MAC_SIZE_BYTES] = nonce[i];
            }
            return output;
        }

    }

    public static void main(String[] args){
        byte[] bytes = {50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4,50,2,3,4, 1, 2, 3, 4};
        AuthDecryptor dec = new AuthDecryptor(bytes);
        AuthEncryptor enc = new AuthEncryptor(bytes);

    }
}