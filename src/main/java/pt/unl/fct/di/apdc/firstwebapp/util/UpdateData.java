package pt.unl.fct.di.apdc.firstwebapp.util;

public class UpdateData {
    public String targetUsername;
    public String email;
    public String phone;
    public String address;

    public UpdateData(){}
    public UpdateData(String targetUsername,String email,String address,String phone){
        this.address = address;
        this.email = email;
        this.targetUsername=targetUsername;
        this.phone = phone;
    }
}
