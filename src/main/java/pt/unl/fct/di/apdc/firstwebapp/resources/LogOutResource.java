package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.datastore.*;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // alterar a codificacao para UTF-8
public class LogOutResource {
    public LogOutResource() {
    }

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

    @Path("/v1")
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // alterar a codificacao para UTF-8
    public Response logOut(@HeaderParam("Authorization") String authToken) {
        if (authToken == null || authToken.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Token de autorização não fornecido").build();
        }

        // Extrai o token do cabeçalho
        String tokenString = authToken.substring(7); // Remove "Bearer " do início
        AuthToken token = null;
        try {
            token = new ObjectMapper().readValue(tokenString, AuthToken.class);
        } catch (IOException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Token inválido").build();
        }

        // Verifica se o token expirou
        if (token.isExpired()) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Token expirado").build();
        }

        // Cria a chave para o token no Datastore
        Key tokenKey = datastore.newKeyFactory()
                .addAncestor(PathElement.of("User", token.getUsername()))
                .setKind("UserToken")
                .newKey(token.tokenID);

        // Deleta o token do Datastore
        datastore.delete(tokenKey);

        // Retorna uma resposta indicando que o logout foi bem-sucedido
        return Response.ok("Logout realizado com sucesso").build();
    }
}
