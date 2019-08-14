package encryp;
import java.io.File;
public class TestEnDe {
	    public static void main(String[] args) {
	        String key = "Mary has one cat";
	        File inputFile = new File("/home/harmanjeet/Downloads/Chronic_Kidney_Disease/chronic_kidney_disease.arff");
	        File encryptedFile = new File("document.encrypted");
	        File decryptedFile = new File("document.decrypted");
	         
	        try {
	            EnDe.encrypt(key, inputFile, encryptedFile);
	            EnDe.decrypt(key, encryptedFile, decryptedFile);
	        } catch (CryptoException ex) {
	            System.out.println(ex.getMessage());
	            ex.printStackTrace();
	        }
	    }
	}


