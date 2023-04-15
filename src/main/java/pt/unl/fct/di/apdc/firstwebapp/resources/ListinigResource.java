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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
        if (token.isExpired()) {

            permissions.deleteToken(token.tokenID,token.username);
            return Response.status(Response.Status.UNAUTHORIZED).entity("Token expirado").build();
        }
        Key userKey = userKeyFactory.newKey(token.getUsername());
        Entity user = datastore.get(userKey);

        if (user == null) {
            LOG.warning("User not found");
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        String role = user.getString("user_role").toUpperCase();

        List<Entity> allowedUsers = new ArrayList<>();
        LoginData.UserRole userRole = LoginData.UserRole.valueOf(role) ;

        EntityQuery query = Query.newEntityQueryBuilder().setKind("User").build();
        QueryResults<com.google.cloud.datastore.Entity> results = datastore.run(query);

        if(role.equals("USER")) {
            StructuredQuery.Filter roleFilter = StructuredQuery.PropertyFilter.eq("user_role", "USER");
            StructuredQuery.Filter profileFilter = StructuredQuery.PropertyFilter.eq("user_perfil", "PUBLICO");
            StructuredQuery.Filter stateFilter = StructuredQuery.PropertyFilter.eq("user_state", "ATIVO");
            StructuredQuery.CompositeFilter compositeFilter = StructuredQuery.CompositeFilter.and(roleFilter, profileFilter, stateFilter);


            Query<Entity> query2 = Query.newEntityQueryBuilder()
                    .setKind("User")
                    .setFilter(compositeFilter)
                    .build();
            QueryResults<Entity> results2 = datastore.run(query);

            List<Map<String, String>> users = new ArrayList<>();
            while (results2.hasNext()) {
                Entity entity = results2.next();

                String username = String.valueOf(entity.getKey().getName());

                String email = entity.getString("user_email");
                String name = entity.getString("user_name");

                Map<String, String> userAlt = new HashMap<>();
                userAlt.put("username", username);
                userAlt.put("email", email);
                userAlt.put("name", name);

                users.add(userAlt);

            }
            String jsonResponse = g.toJson(users);

            return Response.ok(jsonResponse).build();
        }else{

            for (QueryResults<com.google.cloud.datastore.Entity> it = results; it.hasNext(); ) {
                com.google.cloud.datastore.Entity user2 = it.next();
                String userRoleTarget = user2.getString("user_role").toUpperCase();

                LoginData.UserRole targetRole = LoginData.UserRole.valueOf(userRoleTarget);

                if (permissions.canSeeUser(targetRole, userRole)) allowedUsers.add(user2);
            }
            String jsonResponse = g.toJson(allowedUsers);
            return Response.ok(jsonResponse).build();
        }
    }

}
