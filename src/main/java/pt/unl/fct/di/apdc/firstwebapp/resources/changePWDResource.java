package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/change-password")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")//alterar a codificacao para UTF-8
public class changePWDResource {

    changePWDResource(){}
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    @POST
    @Path("/v1")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")

    public Response changePassword(@Valid  @NotNull ChangePasswordData data){

        if(!data.getConfirmPassword().equals(data.getNewPassword())){
            return Response.status(Response.Status.FORBIDDEN).entity("Make sure that the passwords are equal").build();
        }
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.getUsername());
        Entity user = datastore.get(userKey);
        String currentPasswordHash = DigestUtils.sha512Hex(data.getCurrentPassword());
        String storedPasswordHash = user.getString("user_pwd");
        if(!currentPasswordHash.equals(storedPasswordHash)){
            return Response.status(Response.Status.FORBIDDEN).entity("Wrong password").build();
        }
        Transaction txn = datastore.newTransaction();
        try{
            String newPasswordHashed = DigestUtils.sha512Hex(data.getNewPassword());
            Entity Updateuser = Entity.newBuilder(userKey)
                    .set("user_name", user.getString("user_name"))
                    .set("user_pwd", newPasswordHashed)
                    .set("user_email", user.getString("user_email"))
                    .set("user_creation_time", user.getString("user_creation_time"))
                    .build();

            txn.put(Updateuser);
            txn.commit();
            return Response.ok("The password was changed").build();
        }finally{
            if(txn.isActive()){
                txn.rollback();
            }

        }

    }

}
