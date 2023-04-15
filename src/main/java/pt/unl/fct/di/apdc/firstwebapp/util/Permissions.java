package pt.unl.fct.di.apdc.firstwebapp.util;

import com.google.cloud.datastore.*;
import pt.unl.fct.di.apdc.firstwebapp.resources.LoginResource;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData.UserRole;

import java.util.logging.Logger;

public class Permissions {
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    public boolean canRemoveUser(UserRole targetUser, UserRole user) {
        switch (user) {
            case SU:
                return true;
            case GS:
                return targetUser == UserRole.GA || targetUser == UserRole.GBO || targetUser == UserRole.USER;
            case GA:
                return targetUser == UserRole.GBO || targetUser == UserRole.USER;
            case GBO:
                return targetUser == UserRole.USER;
            case USER:
                return user.equals(targetUser);
            default:
                return false;
        }
    }

    public boolean canSeeUser(UserRole targetRole, UserRole user) {
        switch (user) {

            case GBO:
                if (targetRole == UserRole.USER) {
                    return true;
                }
                break;
            case GA:
                if (targetRole == UserRole.USER || targetRole == UserRole.GBO) {
                    return true;
                }
                break;
            case GS:
                if (targetRole == UserRole.USER || targetRole == UserRole.GBO || targetRole == UserRole.GA) {
                    return true;
                }
                break;
            case SU:
                    return true;

            default:
                throw new IllegalStateException("Unexpected value: " + user);


        }


        return false;
    }
    public boolean canModifyUser(UserRole userRole, UserRole targetUserRole) {
        switch (userRole) {
            case SU:
                return targetUserRole == UserRole.GS || targetUserRole == UserRole.GBO || targetUserRole == UserRole.USER;
            case GS:
                return targetUserRole == UserRole.GBO || targetUserRole == UserRole.USER;
            case GBO:
                return targetUserRole == UserRole.USER;
            case USER:
                return false;
            default:
                return false;
        }
    }
    public boolean canModifyState(UserRole userRole, UserRole targetUserRole) {
        switch (userRole) {
            case SU:
                return targetUserRole == UserRole.GS || targetUserRole == UserRole.GBO || targetUserRole == UserRole.USER;
            case GS:
                return targetUserRole == UserRole.GBO || targetUserRole == UserRole.GA;
            case GA:
                return targetUserRole == UserRole.GBO || targetUserRole == UserRole.USER;
            case GBO:
                return targetUserRole == UserRole.USER;
            case USER:
                return targetUserRole == UserRole.USER;
            default:
                return false;
        }
    }
    public void updateToken (String role,String tokenID,String username){

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("UserToken")
                .newKey(tokenID);
        Entity token = datastore.get(tokenKey);
        Entity updateToken = Entity.newBuilder(tokenKey)
                .set("username", token.getString("username"))
                .set("creationData", token.getString("creationData"))
                .set("expirationData",token.getString("expirationData"))
                .set(("tokenID"),token.getString("tokenID"))
                .set("role",role)
                .build();
                datastore.put(updateToken);
    }
    public void deleteToken (String tokenID,String username){
        Transaction txn = datastore.newTransaction();
        try{
        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("UserToken")
                .newKey(tokenID);


        datastore.delete(tokenKey);
        }catch (Exception e){
            LOG.warning("error: "+ e);
        }
    }

}


