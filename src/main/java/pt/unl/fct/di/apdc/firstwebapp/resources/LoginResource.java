package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;


import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.gson.Gson;
import com.google.cloud.datastore.*;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData2;


@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")//alterar a codificacao para UTF-8
public class LoginResource {

	/**
	 * Logger Object
	 */

	private final Gson g = new Gson();
	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private  final KeyFactory userKeyFactory =  datastore.newKeyFactory().setKind("User");
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

	public LoginResource() {}


	@Path("/v1")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response loginUser(LoginData2 loginData) {
		// Validação dos atributos obrigatórios
		if (loginData.getIdentifier() == null || loginData.getIdentifier().isEmpty()
				|| loginData.getPassword() == null || loginData.getPassword().isEmpty()) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Atributos obrigatórios estão faltando ou são inválidos").build();
		}

		// Busca o usuário no banco de dados usando o identificador (pode ser username, email ou userId)
		Entity user = findUserByIdentifier(loginData.getIdentifier());

		// Verifica se o usuário existe e se a senha está correta
		if (user == null || !DigestUtils.sha512Hex(loginData.getPassword()).equals(user.getString("user_pwd"))) {
			return Response.status(Response.Status.UNAUTHORIZED).entity("Credenciais inválidas").build();
		}

		String jsonResponse = g.toJson(user);
		// Gera um novo token de sessão

		AuthToken authToken = new AuthToken(loginData.getIdentifier(),user.getString("user_role"));

		// Salva o token no banco de dados (opcional)

		// Retorna o token ao usuário
		return Response.ok(g.toJson(authToken)).build();
	}

	private Entity findUserByIdentifier(String identifier) {
		// Implemente a lógica para buscar o usuário no banco de dados usando o identificador (username, email ou userId)
		LOG.warning(identifier);
		Key userKey = userKeyFactory.newKey(identifier);
		Entity user = datastore.get(userKey);
		return user;
	}
	@Path("/getToken")
	@GET
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getToken( @HeaderParam("Authorization") String authToken) {
		if (authToken == null || authToken.isEmpty()) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Atributos obrigatórios estão faltando ou são inválidos").build();
		}

		// Extrai o token do cabeçalho
		String tokenString = authToken.substring(6); // Remove "Bearer " do início
		AuthToken token = null;
		try {
			token = new ObjectMapper().readValue(tokenString, AuthToken.class);
		} catch (IOException e) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Token inválido " + e).build();
		}
		if (token.isExpired()) {
			return Response.status(Response.Status.UNAUTHORIZED).entity("Token expirado").build();
		}
		LOG.warning(token.tokenID);
		Key TokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", token.getUsername())).setKind("UserToken")
				.newKey((token.tokenID));
		Transaction txn = datastore.newTransaction();
		try{
		Entity tokenEntity = txn.get(TokenKey);
		if(tokenEntity == null){
				return Response.status(Response.Status.BAD_REQUEST).entity("O token nao esta valido").build();
			}
		return Response.ok(g.toJson(tokenEntity)).build();
		}finally {
			if (txn.isActive()) {
				txn.rollback();
			}
		}

	}
	@Path("/getUser")
	@GET
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getUser( @HeaderParam("Authorization") String authToken) {
		if (authToken == null || authToken.isEmpty()) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Atributos obrigatórios estão faltando ou são inválidos").build();
		}

		// Extrai o token do cabeçalho
		String tokenString = authToken.substring(6); // Remove "Bearer " do início
		AuthToken token = null;
		try {
			token = new ObjectMapper().readValue(tokenString, AuthToken.class);
		} catch (IOException e) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Token inválido " + e).build();
		}
		if (token.isExpired()) {
			return Response.status(Response.Status.UNAUTHORIZED).entity("Token expirado").build();
		}
		Key userKey = userKeyFactory.newKey(token.getUsername());
		Entity user = datastore.get(userKey);
		String username = String.valueOf(user.getKey().getName());

		String email = user.getString("user_email");
		String name = user.getString("user_name");
		String role = user.getString("user_role");
		String perfil = user.getString("user_perfil");
		String state = user.getString("user_state");
		String phone = user.getString("user_phone");
		String address = user.getString("user_address");
		String nif = user.getString("user_nif");
		String ocupacao = user.getString("user_ocupation");
		Map<String, String> userAlt = new HashMap<>();
		userAlt.put("user_name", name);
		userAlt.put("user_email", email);
		userAlt.put("user_role", role);
		userAlt.put("user_perfil", perfil);
		userAlt.put("user_state", state);
		userAlt.put("user_phone", phone);
		userAlt.put("user_address", address);
		userAlt.put("user_nif", nif);
		userAlt.put("user_ocupation",ocupacao);


		//passar para uma string
		return Response.ok(g.toJson(userAlt)).build();
	}

}
