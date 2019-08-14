package xml.encryp;


	import javax.xml.parsers.DocumentBuilderFactory;
	import javax.crypto.Cipher;
	import javax.crypto.KeyGenerator;
	import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.xml.parsers.DocumentBuilder;
	import org.w3c.dom.Document;
	import org.w3c.dom.NodeList;
	import org.w3c.dom.Node;
	import org.w3c.dom.Element;
	import java.io.File;
	import sun.misc.BASE64Encoder;
	import sun.misc.BASE64Decoder;
	
	public class xmlsearch {
		private static SecretKey secretKeyDesKey = null;
		public static void main(String argv[]) {
			

		    try {	
			File fXmlFile = new File("/home/harmanjeet/Desktop/workspace1/XMLEncryp/XmlEncryptionTestEncryptedNodes.xml");
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);
					
			//optional, but recommended
			//read this - http://stackoverflow.com/questions/13786607/normalization-in-dom-parsing-with-java-how-does-it-work
			doc.getDocumentElement().normalize();

			System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
					
			NodeList nList = doc.getElementsByTagName("EncryptedData");
			NodeList nlEncryptedData = doc.getElementsByTagName("EncryptedData");
			Element elEncryptedData = (Element) nlEncryptedData.item(0);
			byte[] bytesDecryptionKey = getDecryptionKeyBytes(elEncryptedData);
			System.out.println("bytesDecryptionKey"+bytesDecryptionKey.toString());
			try {
				
				secretKeyDesKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(bytesDecryptionKey));
				System.out.println("secretDecryptionKey"+secretKeyDesKey.toString());
	        } catch (Exception ex) {
	            
	            ex.printStackTrace();
	        }
			String string ="Robin";
	    	byte[] bytesToBeEncrypted = string.getBytes();
	    	byte[] bytesCiphertext = null;
	    	try {
	            Cipher cipherDes = Cipher.getInstance("DES/ECB/PKCS5Padding");
	            cipherDes.init(Cipher.ENCRYPT_MODE, secretKeyDesKey);

	            bytesCiphertext = cipherDes.doFinal(bytesToBeEncrypted);   
	        } catch (Exception ex) {
	            System.out.println("Exception: ");
	            ex.printStackTrace();
	        }        
	    	String base64EncodedElement = base64Encode(bytesCiphertext);
	    	
					
			System.out.println("----------------------------");

			for (int temp = 0; temp < nList.getLength(); temp++) {

				Node nNode = nList.item(temp);
						
				System.out.println("\nCurrent Element :" + nNode.getNodeName()+"temp"+temp);
						
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {

					Element eElement = (Element) nNode;
					System.out.println(" Cipher Text : " + eElement.getElementsByTagName("CipherText").item(0).getTextContent());
					String reqData=eElement.getElementsByTagName("CipherText").item(0).getTextContent();
					if(reqData.equalsIgnoreCase(base64EncodedElement))
						{
						System.out.println("Match Found");
						}
				}
				System.out.println("Match Found"+base64EncodedElement+" hi "+ bytesCiphertext);
			}
			
					/*NodeList nl = eElement.getElementsByTagName("DecryptionInfo").item(temp).getChildNodes();
					for (int i=0; i < nl.getLength(); i++) {
					    
					    Node node = nl.item(i);

						if (node.getNodeType() == Node.TEXT_NODE) {
							String reqData=eElement.getElementsByTagName("CipherText").item(i).getTextContent();
							System.out.println("val"+reqData);
						}
					}
					//String reqData=eElement.getElementsByTagName("CipherText").item(0).getTextContent();
					//if(reqData.equalsIgnoreCase(base64EncodedElement))
						//{
						//System.out.println("Match Found");
						//}
					

				}*/
			
		    } catch (Exception e) {
			e.printStackTrace();
		    }
		  }
		private static String base64Encode(byte[] in) {
		    
		    BASE64Encoder encoder = new BASE64Encoder();
		    
		    return encoder.encode(in);	
		}


		private static byte[] base64Decode(String strIn) {
		    
		    BASE64Decoder decoder = new BASE64Decoder();
		    
		    byte[] bytesOut = null;
		    
		    try {
		        bytesOut = decoder.decodeBuffer(strIn);
		    } catch (Exception ex) {
		        ex.printStackTrace();
		    }
		    
		    return bytesOut;	
		}	
		private static byte[] getDecryptionKeyBytes(Element elEncryptedData) {
		    
		    Element elDecryptionInfo = (Element) elEncryptedData.getElementsByTagName("DecryptionInfo").item(0);
		    
		    Element elKeyValue = (Element) elDecryptionInfo.getElementsByTagName("Value").item(0);
		    
		    StringBuffer strbufKeyBytes = new StringBuffer();
		    
			NodeList nl = elKeyValue.getChildNodes();

			for (int i=0; i < nl.getLength(); i++) {
			    
			    Node node = nl.item(i);

				if (node.getNodeType() == Node.TEXT_NODE) {
					
					strbufKeyBytes.append(node.getNodeValue());
				}
			}
			
			return base64Decode(strbufKeyBytes.toString().trim());		
		}
	}





