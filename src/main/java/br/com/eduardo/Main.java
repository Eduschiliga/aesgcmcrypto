package br.com.eduardo;

import br.com.eduardo.model.Usuario;
import br.com.eduardo.model.WrapperJson;
import com.fasterxml.jackson.databind.ObjectMapper;

import static br.com.eduardo.AesGcmCrypto.decrypt;
import static br.com.eduardo.AesGcmCrypto.encrypt;
import static java.lang.System.out;

public class Main {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    static void main() throws Exception {
        Usuario usuario = new Usuario(
                "Eduardo",
                "email@gmail.com",
                "GnaX@djl@d_!65Ad_+S>;"
        );

        out.println("Usuario antes da criptografia: " + usuario);

        String json = encrypt(usuario);
        WrapperJson wrapperJson = new WrapperJson(json);

        out.println("Usuario depois da criptografia: " + wrapperJson);

        String jsonDecriptografado = decrypt(wrapperJson.payload());

        Usuario usuarioDeserializado = objectMapper.readValue(jsonDecriptografado, Usuario.class);

        out.println("Usuario descriptografado: " + usuarioDeserializado.toString());
    }
}
