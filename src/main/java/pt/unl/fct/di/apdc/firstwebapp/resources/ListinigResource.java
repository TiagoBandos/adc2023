package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.util.Permissions;


import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@Path("/listUser")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")//alterar a codificacao para UTF-8
public class ListinigResource {
    public ListinigResource() {
    }
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private Permissions permissions = new Permissions();
    private final Gson g = new Gson();
    private  final KeyFactory userKeyFactory =  datastore.newKeyFactory().setKind("User");
    @GET
    @Path("/v1")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response listUsers( @HeaderParam("Authorization") String authToken) {

        String tokenString = authToken.substring(6); // Remove "Bearer " do início
        AuthToken token = null;
        try {
            token = new ObjectMapper().readValue(tokenString, AuthToken.class);
        } catch (IOException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Token inválido " + e).build();
        }
        Key userKey = userKeyFactory.newKey(token.getUsername());// perguntar o pq do stor so ter
        // posto o userKeyfactory
        LOG.warning(String.valueOf(userKey));
        Entity user = datastore.get(userKey);
        if (user == null) {
            LOG.warning("User not found");
            return Response.status(Response.Status.FORBIDDEN).build();
        }


        List<Entity> allowedUsers = new ArrayList<>();
        LoginData.UserRole userRole = LoginData.UserRole.valueOf(user.getString("role")) ;
        EntityQuery query = Query.newEntityQueryBuilder().setKind("User").build();
        QueryResults<com.google.cloud.datastore.Entity> results = datastore.run(query);

        for (QueryResults<com.google.cloud.datastore.Entity> it = results; it.hasNext(); ) {
            com.google.cloud.datastore.Entity user2 = it.next();

            LoginData.UserRole targetRole = LoginData.UserRole.valueOf(user2.getString("role"));

            if (permissions.canSeeUser(targetRole, userRole)) allowedUsers.add(user2);
        }
        String jsonResponse = g.toJson(allowedUsers);;
        return Response.ok(jsonResponse).build();
    }

}
