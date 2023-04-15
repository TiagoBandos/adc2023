package pt.unl.fct.di.apdc.firstwebapp.util;



public class LoginData {

	public enum UserRole {
		USER, GBO, GA, GS, SU
	}

	public String username;
	public String password;
	public String name;
	public String email;
	public String perfil;
	public String morada;
	public UserRole role;

	public LoginData() {

	}

	public LoginData(String username, String password, String name, String email) {
		this.username = username;
		this.password = password;
		this.name = name;
		this.email = email;
		this.perfil = null;
		this.morada = null;
		this.role = UserRole.USER;

	}

	public boolean validRegistration() {

		return this.username != null && this.password != null && this.name != null && this.email != null;
	}

	public boolean validPassword() {
		return password.length() > 9 && password.matches(".*\\d.*");

	}	
	public UserRole getRole() {
		// TODO Auto-generated method stub
		return role;
	}
	 public boolean canChangeState(UserRole	 targetUser) {
	        switch (this.role) {
	            case SU:
	                return true;
	            case GS:
	                return targetUser == UserRole.GA || targetUser == UserRole.GBO;
	            case GA:
	                return targetUser == UserRole.GBO || targetUser == UserRole.USER;
	            case GBO:
	                return targetUser == UserRole.USER;
	            case USER:
	                return this.equals(targetUser);
	            default:
	                return false;
	        }
	    }
	 public boolean canRemoveUser(UserRole	 targetUser) {
	        switch (this.role) {
	            case SU:
	                return true;
	            case GS:
	                return targetUser == UserRole.GA || targetUser == UserRole.GBO || targetUser == UserRole.USER;
	            case GA:
	                return targetUser == UserRole.GBO || targetUser == UserRole.USER;
	            case GBO:
	                return targetUser == UserRole.USER;
	            case USER:
	                return this.equals(targetUser);
	            default:
	                return false;
	        }
	    }


}
