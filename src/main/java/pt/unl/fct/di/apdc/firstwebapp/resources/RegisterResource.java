package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;


import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.regex.Pattern;

import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.StringValue;
import com.google.cloud.datastore.Transaction;
import com.google.gson.Gson;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.util.UserResgistrationData;


@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8") // alterar a codificacao para UTF-8
public class RegisterResource {
	public RegisterResource() {
	}
	private static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$");

	// Verifica se o email é válido
	private static boolean isValidEmail(String email) {
		return EMAIL_PATTERN.matcher(email).matches();
	}
	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private  final KeyFactory userKeyFactory =  datastore.newKeyFactory().setKind("User");
	private  final KeyFactory tokenKeyFactory =  datastore.newKeyFactory();
	private final Gson g = new Gson();


	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response registerUser(UserResgistrationData registrationData) {
		// Validação dos atributos obrigatórios
		if (registrationData.getUsername() == null || registrationData.getUsername().isEmpty()
				|| registrationData.getEmail() == null || registrationData.getEmail().isEmpty()
				|| !isValidEmail(registrationData.getEmail())
				|| registrationData.getName() == null || registrationData.getName().isEmpty()
				|| registrationData.getPassword() == null || registrationData.getPassword().isEmpty()) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Atributos obrigatórios estão faltando ou são inválidos").build();
		}

		// Validação da senha
		// Exemplo de regra de senha: pelo menos 8 caracteres, incluindo pelo menos uma letra maiúscula, uma letra minúscula e um número
		if (!registrationData.getPassword().matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$")) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Senha inválida: deve conter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma letra minúscula e um número").build();
		}

		// Verifica se as senhas correspondem
		if (!registrationData.getPassword().equals(registrationData.getConfirmPassword())) {
			return Response.status(Response.Status.BAD_REQUEST).entity("As senhas não correspondem").build();
		}
		Transaction txn = datastore.newTransaction();
		try {
			Key userKey = userKeyFactory.newKey(registrationData.getUsername());
			Entity user = txn.get(userKey);

			if (user != null) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("Usuário já existe").build();
			} else {
				AuthToken authToken = new AuthToken(registrationData.getUsername(),"USER");


				Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", registrationData.getUsername())).setKind("UserToken")
						.newKey((authToken.tokenID));
				Entity tokenEntity = Entity.newBuilder(tokenKey)
						.set("username", registrationData.getUsername())
						.set("creationData", authToken.creationData)
						.set("expirationData", authToken.expirationData)
						.set(("tokenID"),authToken.tokenID)
						.set("role",authToken.role)
						.build();
//perguntar ao professor como é que eu posso adicionar as fotografias, como é que eu posso so atualizar as propriedades que quero ser alterar as outras
				user = Entity.newBuilder(userKey)
						.set("user_name", registrationData.getName())
						.set("user_pwd", DigestUtils.sha512Hex(registrationData.getPassword()))
						.set("user_email", registrationData.getEmail())
						.set("user_role", "USER")
						.set("user_perfil","PUBLICO")
						.set("user_state","INATIVO")
						.set("user_phone","")
						.set("user_address","")
						.set("user_ocupation","")
						.set("user_nif","")
						.set("user_creation_time", Timestamp.now()).build();
				// executa a escrita
				LOG.info("User registered" + registrationData.getUsername());

				// Salva as entidades no Datastore
				txn.add(user, tokenEntity);
				// confirma a transação
				txn.commit();
				return Response.ok(g.toJson(authToken)).build();
			}
		} catch (Exception e) {
			if (txn.isActive()) {
				txn.rollback();
			}

			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Houve conflito").build();
			// Retorna a resposta de sucesso

		}

	}


	@SuppressWarnings("finally")
	@POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response registerV2(LoginData regist) {
		LOG.fine("Attempt to register user" + regist.username);
		if (!regist.validRegistration()) {

			return Response.status(Status.FORBIDDEN).entity("missing parameter").build();
		}
		Transaction txn = datastore.newTransaction();
		try {
			Key userKey = userKeyFactory.newKey(regist.username);
			Entity user = txn.get(userKey);
			if (user != null) {
				txn.rollback();// aborta a transição pois ja existe user
				return Response.ok("User already exists " + regist.role.name() ).build();
			} else {
				user = Entity.newBuilder(userKey)
						.set("user_name", regist.name)
						.set("user_pwd", DigestUtils.sha512Hex(regist.password))
						.set("user_email", regist.email)
						.set("role","User")
						.set("user_creation_time", Timestamp.now()).build();
				txn.add(user);// executa a escrita
				LOG.info("User registered" + regist.username);
				txn.commit();// confirma a transação
				return Response.ok("User was created " + regist.role.name() ).build();

			}
		} finally {
			if (txn.isActive()) {
				txn.rollback();
			}
			return Response.ok("{}").build();
		}

	}

}
