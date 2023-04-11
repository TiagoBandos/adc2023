package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.util.Permissions;
import pt.unl.fct.di.apdc.firstwebapp.util.UpdateData;

import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // alterar a codificacao para UTF-8
public class UpdateResource {
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private  final KeyFactory userKeyFactory =  datastore.newKeyFactory().setKind("User");
    private Permissions permissions = new Permissions();
    @Path("/v1")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateUserAttributes(@Context HttpHeaders headers, UpdateData updateData) {
        if (updateData == null || headers.getHeaderString("username") == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Dados inválidos").build();
        }

        Key userKey = userKeyFactory.newKey(headers.getHeaderString("username"));
        Entity user = datastore.get(userKey);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Usuário não encontrado").build();
        }

        LoginData.UserRole userRole = LoginData.UserRole.valueOf(user.getString("role"));
        // Carrega o usuário alvo
        Key targetUserKey = userKeyFactory.newKey(updateData.targetUsername);
        Entity targetUser = datastore.get(targetUserKey);
        if (targetUser == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Usuário alvo não encontrado").build();
        }
        LoginData.UserRole targetRole = LoginData.UserRole.valueOf(targetUser.getString("role"));
        // Verifica se o usuário pode modificar a conta alvo
        if (!permissions.canModifyUser(targetRole, userRole)) {
            return Response.status(Response.Status.FORBIDDEN).entity("Permissões insuficientes").build();
        }


        Transaction txn = datastore.newTransaction();
        try{
        // Atualiza os atributos permitidos
        Entity.Builder updatedUserBuilder = Entity.newBuilder(targetUser);

        if (userRole != LoginData.UserRole.USER) {
            updatedUserBuilder.set("email", updateData.email);
        }
        if (updateData.phone != null) {
            updatedUserBuilder.set("phone", updateData.phone);
        }
        if (updateData.address != null) {
            updatedUserBuilder.set("address", updateData.address);
        }


        // Salva o usuário atualizado no Datastore
        txn.put(updatedUserBuilder.build());

        return Response.ok("Atributos do usuário atualizados com sucesso").build();
        }finally{
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }
}
