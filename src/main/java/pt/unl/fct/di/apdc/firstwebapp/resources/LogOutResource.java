package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.Permissions;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.logging.Logger;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // alterar a codificacao para UTF-8
public class LogOutResource {
    public LogOutResource() {
    }

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private final Gson g = new Gson();
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private Permissions permissions = new Permissions();
    @Path("/v1")
    @POST
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // alterar a codificacao para UTF-8
    public Response logOut(@HeaderParam("Authorization") String authToken) {
        if (authToken == null || authToken.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Token de autorização não fornecido").build();
        }

        // Extrai o token do cabeçalho
        String tokenString = authToken.substring(6); // Remove "Bearer " do início
        AuthToken token = null;
        try {
            token = new ObjectMapper().readValue(tokenString, AuthToken.class);
        } catch (IOException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Token inválido "+ e).build();
        }

        // Verifica se o token expirou
        if (token.isExpired()) {
            permissions.deleteToken(token.tokenID,token.username);
            return Response.status(Response.Status.UNAUTHORIZED).entity("Token expirado").build();
        }

        Transaction txn = datastore.newTransaction();
        try {


            // Cria a chave para o token no Datastore
            Key tokenKey = datastore.newKeyFactory()
                    .addAncestor(PathElement.of("User", token.getUsername()))
                    .setKind("UserToken")
                    .newKey(token.tokenID);


            // Deleta o token do Datastore
            txn.delete(tokenKey);

            txn.commit();
            Entity tokenEntity = datastore.get(tokenKey);
            LOG.warning(g.toJson(tokenEntity));
            // Retorna uma resposta indicando que o logout foi bem-sucedido
            return Response.ok("Logout realizado com sucesso").build();
        }finally {
            if (txn.isActive()) {
                txn.rollback();
            }

        }
    }
}
