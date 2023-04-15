package pt.unl.fct.di.apdc.firstwebapp.util;

public class UpdateData {
    public String targetUsername;
    public String email;
    public String phone;
    public String address;
    public String role;


    public String estado;
    public String ocupacao;
    public  String nome;

    public String nif;
    public UpdateData(){}
    public UpdateData(String targetUsername,String email,String address,String phone,String role,String Estado,String ocupacao,String nif,String nome){
        this.address = address;
        this.email = email;
        this.targetUsername=targetUsername;
        this.phone = phone;
        this.role = role;
        this.estado = Estado;
        this.nif = nif;
        this.ocupacao = ocupacao;
        this.nome = nome;
    }
}
