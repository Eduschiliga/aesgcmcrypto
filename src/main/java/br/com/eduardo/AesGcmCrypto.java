package br.com.eduardo;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM.
 * <p>
 * Especificações Criptográficas
 * Algoritmo: AES (Advanced Encryption Standard)
 * Modo de Operação: GCM (Galois/Counter Mode)
 * Padding: Nenhum (NoPadding - o GCM é uma cifra de fluxo, não exige padding)
 * Tamanho da Chave Secreta (Key Size): 256 bits (32 bytes)
 * Tamanho do Vetor de Inicialização (IV / Nonce): 96 bits (12 bytes)
 * Tamanho da Tag de Autenticação (Auth Tag / MAC): 128 bits (16 bytes)
 * Codificação do texto original: UTF-8
 * Codificação final para tráfego: Base64
 * <p>
 * O array de bytes que foi codificado em Base64 segue exatamente esta estrutura e ordem:
 * Os primeiros 12 bytes: Vetor de Inicialização (IV).
 * O restante dos bytes até os últimos 16: O texto cifrado em si.
 * Os últimos 16 bytes: A Tag de Autenticação.
 * */
public class AesGcmCrypto {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private static final byte[] secretKey = Base64.getDecoder()
            .decode("vT8+Rq+rV+I/mD6t2yL8+Xk1p3A/cT5hJ6uF8vW0z+Y=");

    public static String encrypt(Object object) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        String rawJson = objectMapper.writeValueAsString(object);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(secretKey, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BIT, iv)
        );

        byte[] cipherText = cipher.doFinal(rawJson.getBytes(StandardCharsets.UTF_8));

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    public static String decrypt(String base64EncryptedData) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(base64EncryptedData);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        System.arraycopy(decodedData, 0, iv, 0, IV_LENGTH_BYTE);

        byte[] cipherText = new byte[decodedData.length - IV_LENGTH_BYTE];
        System.arraycopy(decodedData, IV_LENGTH_BYTE, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(secretKey, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BIT, iv)
        );

        byte[] plainTextBytes = cipher.doFinal(cipherText);

        return new String(plainTextBytes, StandardCharsets.UTF_8);
    }
}