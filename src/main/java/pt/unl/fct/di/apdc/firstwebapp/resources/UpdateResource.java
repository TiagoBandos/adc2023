package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.util.Permissions;
import pt.unl.fct.di.apdc.firstwebapp.util.UpdateData;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.logging.Logger;

@Path("/update")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // alterar a codificacao para UTF-8
public class UpdateResource {
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private final Gson g = new Gson();
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private Permissions permissions = new Permissions();

    @Path("/v1")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateUserAttributes(@HeaderParam("Authorization") String authToken, UpdateData updateData) {
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

        Key userKey = userKeyFactory.newKey(token.username);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Usuário não encontrado " + token.username + "   " + authToken).build();
        }


        LoginData.UserRole userRole = LoginData.UserRole.valueOf(user.getString("user_role").toUpperCase());
        // Carrega o usuário alvo
        ;
        Key targetUserKey = userKeyFactory.newKey(updateData.targetUsername);
        Entity targetUser = datastore.get(targetUserKey);

        if (targetUser == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Usuário alvo não encontrado").build();
        }
        LoginData.UserRole targetRole = LoginData.UserRole.valueOf(targetUser.getString("user_role").toUpperCase());
        // Verifica se o usuário pode modificar a conta alvo
        if (!user.equals(targetUser)) {
            if (permissions.canModifyUser(targetRole, userRole)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Permissões insuficientes " +targetRole.toString() + " " + userRole.toString()+permissions.canModifyUser(targetRole, userRole)).build();
            }
        }


        Transaction txn = datastore.newTransaction();
        try {
            // Atualiza os atributos permitidos verificar isto
            Entity.Builder updatedUserBuilder = Entity.newBuilder(targetUserKey);
            updatedUserBuilder
                    .set("user_pwd", targetUser.getString("user_pwd"))
                    .set("user_creation_time", user.getTimestamp("user_creation_time"));
            if (userRole == targetRole) {
                updatedUserBuilder.set("user_role", targetUser.getString("user_role"));
            } else {

                if (updateData.role != null) {
                    if(userRole.toString() == "SU"){
                        updatedUserBuilder.set("user_role", updateData.role.toUpperCase());
                        permissions.updateToken(updateData.role.toUpperCase(), token.tokenID,updateData.targetUsername);
                    }
                    else if (userRole.toString() == "GS" && targetRole.toString() == "USER"){
                        updatedUserBuilder.set("user_role","GBO");
                        permissions.updateToken("GBO", token.tokenID,updateData.targetUsername);
                    }

                } else  {
                    updatedUserBuilder.set("user_role", user.getString("user_role"));
                }
            }
            if (updateData.phone != null) {
                updatedUserBuilder.set("user_phone", updateData.phone);
            } else {
                updatedUserBuilder.set("user_phone", user.getString("user_phone"));
            }
            if (updateData.address != null) {
                updatedUserBuilder.set("user_address", updateData.address);
            } else {
                updatedUserBuilder.set("user_address", user.getString("user_address"));
            }

            if (updateData.estado != null) {
                if(permissions.canModifyState(userRole,targetRole)){
                updatedUserBuilder.set("user_state", updateData.estado.toUpperCase());}

            } else {
                updatedUserBuilder.set("user_state", user.getString("user_state"));
            }
            if (updateData.email != null) {
                updatedUserBuilder.set("user_state", updateData.email);
            } else {
                updatedUserBuilder.set("user_email", user.getString("user_email"));
            }
            if (updateData.nif != null) {
                updatedUserBuilder.set("user_nif", updateData.nif);
            } else {
                updatedUserBuilder.set("user_nif", user.getString("user_nif"));
            }
            if (updateData.ocupacao != null) {
                updatedUserBuilder.set("user_ocupation", updateData.ocupacao);
            } else {
                updatedUserBuilder.set("user_ocupation", user.getString("user_ocupation"));
            }
            if (updateData.nome != null) {
                updatedUserBuilder.set("user_name", updateData.nome);
            } else {
                updatedUserBuilder.set("user_name", user.getString("user_name"));
            }
            // Salva o usuário atualizado no Datastore
            txn.put(updatedUserBuilder.build());
            txn.commit();
            Entity targetEntity = datastore.get(targetUserKey);
            LOG.warning(g.toJson(targetEntity));

            return Response.ok("Atributos do usuário atualizados com sucesso").build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }
}
