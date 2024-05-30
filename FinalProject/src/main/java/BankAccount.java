public class BankAccount {
    private int balance = 1000;

    // Method to deposit money into the account
    public void deposit(int amount) {
        balance += amount;
        System.out.println("New balance: " + balance);
    }

    // Method to withdraw money from the account
    // Returns true if withdrawal is successful, false otherwise
    public boolean withdrawal(int amount) {
        if (balance >= amount) {
            balance -= amount;
            System.out.println("New balance: " + balance);
            return true;
            
        } else {
            return false;
        }
            
    }

    // Method to get the current balance of the account
    public int balance() {
        System.out.println("New balance: " + balance);
        return balance;
    }
}