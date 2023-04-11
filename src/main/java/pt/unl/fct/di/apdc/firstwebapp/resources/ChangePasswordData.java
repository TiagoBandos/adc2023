package pt.unl.fct.di.apdc.firstwebapp.resources;

public class ChangePasswordData {
    public String currentPassword;
    public String newPassword;
    public String confirmPassword;
    public String username;

    public ChangePasswordData() {
    }

    public ChangePasswordData(String currentPassword, String newPassword, String confirmPassword, String username) {
        this.currentPassword = currentPassword;
        this.newPassword = newPassword;
        this.confirmPassword = confirmPassword;
        this.username = username;
    }

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
    // Adicione métodos getter e setter se necessário
}
