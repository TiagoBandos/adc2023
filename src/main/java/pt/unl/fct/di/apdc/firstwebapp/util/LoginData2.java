package pt.unl.fct.di.apdc.firstwebapp.util;

public class LoginData2 {
    private String identifier;
    private String password;

    // Construtores, getters e setters
    LoginData2(){
    }
    LoginData2(String id,String pwd){
        this.identifier = id;
        this.password = pwd;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
