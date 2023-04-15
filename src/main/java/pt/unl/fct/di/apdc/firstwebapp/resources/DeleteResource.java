package pt.unl.fct.di.apdc.firstwebapp.resources;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import autovalue.shaded.org.jetbrains.annotations.NotNull;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.datastore.*;

import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Value;
import com.google.gson.Gson;

import java.io.IOException;
import java.util.logging.Logger;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData.UserRole;
import pt.unl.fct.di.apdc.firstwebapp.util.Permissions;

@Path("/delete")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")//alterar a codificacao para UTF-8
public class DeleteResource {
	public DeleteResource() {}
	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private  final KeyFactory userKeyFactory =  datastore.newKeyFactory().setKind("User");
	private  final KeyFactory tokenKeyFactory =  datastore.newKeyFactory().setKind("AuthToken");
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private final Gson g = new Gson();
	private Permissions permissions = new Permissions();
	
	@SuppressWarnings("finally")
	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
	public Response delete(@Valid @NotNull @QueryParam("usernameR") String usernameR , @Context HttpServletRequest request,
						   @Context HttpHeaders headers,@Valid @NotNull @QueryParam("username") String username){
		//String usernameToken = headers.getHeaderString("username");
		LOG.fine("Attempt to delete user" + usernameR);

			Key userKeyR = datastore.newKeyFactory().setKind("User").newKey(usernameR);//perguntar o pq do stor so ter posto o userKeyfactory
			Entity userR = datastore.get(userKeyR);

		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("UserToken")
				.newKey(("AuthToken"));
		Entity tokenEntity = datastore.get(tokenKey);
		if (tokenEntity == null) {
			return Response.status(Status.BAD_REQUEST).entity("Token inválido").build();
		}
		Transaction txn = datastore.newTransaction();
		//String username = tokenEntity.getString("username");
		Key userKey = userKeyFactory.newKey(username);
		Entity user = txn.get(userKey);

		UserRole targetUserRole = UserRole.valueOf(userR.getString("role"));
		UserRole userRole = UserRole.valueOf(user.getString("role"));
		if(!permissions.canRemoveUser(	targetUserRole,  userRole)) {
			return Response.status(Status.FORBIDDEN).entity("Insufficient permissons").build();
		}
		try {
			txn.delete(userKeyR);
			return Response.ok(" The user: " + username + " removed " + usernameR + " successfully").build();
		}finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}

	}
	@DELETE
	@Path("/v2/{usernameToRemove}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response deleteUser(@PathParam("usernameToRemove") String usernameToRemove,
							   @HeaderParam("Authorization") String authToken) {
		// Validação dos atributos obrigatórios
		if (usernameToRemove == null || usernameToRemove.isEmpty() || authToken == null || authToken.isEmpty()) {
			return Response.status(Status.NO_CONTENT).entity("Atributos obrigatórios estão faltando ou são inválidos").build();
		}

		// Extrai o token do cabeçalho
		String tokenString = authToken.substring(6); // Remove "Bearer " do início
		AuthToken token = null;
		try {
			token = new ObjectMapper().readValue(tokenString, AuthToken.class);
		} catch (IOException e) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Token inválido " + e).build();
		}

		// Verifica se o token expirou
		if (token.isExpired()) {
			permissions.deleteToken(token.tokenID,token.username);
			return Response.status(Response.Status.UNAUTHORIZED).entity("Token expirado").build();
		}

		// Busca informações do usuário que deseja executar a remoção
		Key userKey = userKeyFactory.newKey(token.getUsername());
		Entity user = datastore.get(userKey);
		if (user == null) {
			return Response.status(Response.Status.NOT_FOUND).entity("Usuário não encontrado").build();
		}

		UserRole userRole = UserRole.valueOf(user.getString("user_role").toUpperCase());

		// Busca informações do usuário a ser removido
		Key userKeyToRemove = userKeyFactory.newKey(usernameToRemove);
		Entity userToRemove = datastore.get(userKeyToRemove);
		if (userToRemove == null) {
			return Response.status(Response.Status.NOT_FOUND).entity("Usuário a ser removido não encontrado").build();
		}

		UserRole userRoleToRemove = UserRole.valueOf(userToRemove.getString("user_role").toUpperCase());


		if (!permissions.canRemoveUser(userRole,userRoleToRemove)) {
			return Response.status(Response.Status.FORBIDDEN).entity("Permissões insuficientes").build();
		}

		// Remove o usuário
		Transaction txn = datastore.newTransaction();
		try {
			txn.delete(userKeyToRemove);
			txn.commit();
			return Response.ok("Usuário " + usernameToRemove + " removido com sucesso").build();
		} catch (Exception e) {
			if (txn.isActive()) {
				txn.rollback();
			}
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Erro ao remover usuário").build();
		} finally {
			if (txn.isActive()) {
				txn.rollback();
			}
		}
	}

}
