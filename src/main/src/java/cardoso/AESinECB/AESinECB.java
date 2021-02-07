package main.src.java.cardoso.AESinECB;

import main.src.java.cardoso.AESinECB.useful.BinUtils;
import main.src.java.cardoso.AESinECB.useful.UserInput;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;


public class AESinECB {
    public static void main(String []args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String entrada = UserInput.fileInput("INPUT-AESinECB.txt");
        String key = "YELLOW SUBMARINE";
        System.out.println(key);
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        aes.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(entrada);
        byte[] decrypted = aes.doFinal(decoded);
        String binario = "";
        for (int i = 0; i < decrypted.length; i++) {
            binario += String.format("%8s", Integer.toBinaryString(decrypted[i] & 0xFF)).replace(' ', '0');

        }
        System.out.println(BinUtils.binToManyAscii(binario));

    }
}
