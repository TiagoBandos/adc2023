package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.ChangePasswordData;
import pt.unl.fct.di.apdc.firstwebapp.util.Permissions;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

@Path("/change-password")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")//alterar a codificacao para UTF-8
public class changePWDResource {

   public changePWDResource(){}
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private  final KeyFactory userKeyFactory =  datastore.newKeyFactory().setKind("User");
    private Permissions permissions = new Permissions();
    @PUT //Porque estamos atualizar um user que ja existe
    @Path("/v1")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
// pode ser que acha o risco da password poder ser mudada por users diferentes
    public Response changePassword(@HeaderParam("Authorization") String authToken, @Valid  @NotNull ChangePasswordData data){
        //leitura do token

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

        if (!data.getNewPassword().matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$")) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Senha inválida: deve conter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma letra minúscula e um número").build();
        }
        //confirmar que a password é igual á nova password
        if(!data.getConfirmPassword().equals(data.getNewPassword())){
            return Response.status(Response.Status.FORBIDDEN).entity("Make sure that the passwords are equal").build();
        }
        //buscar o user á data store
        Key userKey = userKeyFactory.newKey(token.username);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Usuário alvo não encontrado" +" "+userKey+ " "+ token.username).build();
        }
        String currentPasswordHash = DigestUtils.sha512Hex(data.getCurrentPassword());
        String storedPasswordHash = user.getString("user_pwd");
        //verificar que a password dada é a correta
        if(!currentPasswordHash.equals(storedPasswordHash)){
            return Response.status(Response.Status.FORBIDDEN).entity("Wrong password").build();
        }
        Transaction txn = datastore.newTransaction();
        try{
            String newPasswordHashed = DigestUtils.sha512Hex(data.getNewPassword());
            Entity Updateuser = Entity.newBuilder(userKey)
                    .set("user_pwd", newPasswordHashed)
                    .set("user_name", user.getString("user_name"))
                    .set("user_email", user.getString("user_email"))
                    .set("user_role", user.getString("user_role"))
                    .set("user_perfil",user.getString("user_perfil"))
                    .set("user_state",user.getString("user_state"))
                    .set("user_phone",user.getString("user_phone"))
                    .set("user_address",user.getString("user_address"))
                    .set("user_ocupation",user.getString("user_ocupation"))
                    .set("user_nif",user.getString("user_nif"))
                    .set("user_creation_time", user.getTimestamp("user_creation_time")).build();

            txn.put(Updateuser);
            txn.commit();
            return Response.ok("The password was changed"+datastore.get(userKey).getString("user_pwd")).build();
        }finally{
            if(txn.isActive()){
                txn.rollback();
            }

        }

    }

}
