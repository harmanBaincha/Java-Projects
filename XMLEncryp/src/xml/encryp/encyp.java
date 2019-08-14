package xml.encryp;

import java.io.*;
import java.security.Security;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.apache.xerces.parsers.DOMParser;
import org.w3c.dom.*;
import org.xml.sax.SAXException;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;


public class encyp {
	private static Document document;
	private static SecretKey secretKeyDesKey = null;
    private static int iDecryptionInfoCounter = 0;

	public static void main(String argv[]) {

	    try {

		
				Security.addProvider(new com.sun.crypto.provider.SunJCE());
				secretKeyDesKey = KeyGenerator.getInstance("DES").generateKey();
			    encrypt();
	    }
	    catch (Exception e) {
			e.printStackTrace();
		}
	    try {

    		String string = secretKeyDesKey.toString();
			
			File fileOut = new File("XmlEncryptionTestEncryptedNodes" + ".xml");
			FileWriter fw = new FileWriter(fileOut);
			PrintWriter pw = new PrintWriter(fw, true);
			
			pw.print(string);
			
			pw.close();
		
		} catch (Exception ex) {
			
			System.out.println("Exception: " + ex);
		}
	}
	
	public static void encrypt() {	    
	    
	    System.out.println("Encrypt...");
        
        String xmlFile = "/home/harmanjeet/Documents/emp.xml"; 

        DOMParser parser = new DOMParser();

        try {
            parser.parse(xmlFile);

        } catch (SAXException se) {
            se.printStackTrace();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }

        document = parser.getDocument();
        encryptChildNodes((Node) document);
        try {

    		String string = getElementAsString(document.getDocumentElement(), false);
			
			File fileOut = new File("XmlEncryptionTestEncryptedNodes" + ".xml");
			FileWriter fw = new FileWriter(fileOut);
			PrintWriter pw = new PrintWriter(fw, true);
			
			pw.print(string);
			
			pw.close();
		
		} catch (Exception ex) {
			
			System.out.println("Exception: " + ex);
		}
	}
	private static void encryptChildNodes(Node nNode) {
        
        NodeList nlChildNodes = nNode.getChildNodes();
        
        for (int i = 0; i < nlChildNodes.getLength(); i++) {
            
            Node nChildNode = nlChildNodes.item(i);
            
            if (nChildNode.getNodeType() == Node.ELEMENT_NODE) {
            	if (nChildNode.getNodeName().equals("Name")||nChildNode.getNodeName().equals("Age")||nChildNode.getNodeName().equals("Id")) {
                    
                    encryptElement((Element) nChildNode, false);
                }
            	NamedNodeMap nnmAttributes = nChildNode.getAttributes();
            	if (nnmAttributes != null) {
                    
                                    
                        Node nAttribute = nnmAttributes.getNamedItem("type1");
                    
                        if (nAttribute != null) {
               
                            encryptAttributeValue((Attr) nAttribute);
                        }
                }
            }
            encryptChildNodes(nChildNode);
        }
	}
	// Encrypt an element.  The boolContentOnly flag controls whether the whole
    // element is encrypted or just the content.
    public static void encryptElement(Element element, boolean boolContentOnly) {
        
        // Get the element, or the element content, as a string.
        String string = getElementAsString(element, boolContentOnly);
        
        // The next part is standard JCA code for encrypting.
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
        
        // Base64 the ciphertext.
        String base64EncodedElement = base64Encode(bytesCiphertext);
        
        Text txtBase64EncodedElement = document.createTextNode(base64EncodedElement);
        
        
        // Create a <DecryptionInfo> element...
        Element elDecryptionInfo = document.createElement("DecryptionInfo");        
   
        setupDecryptionInfo(elDecryptionInfo, secretKeyDesKey);

        // Create the <EncryptedData> element       
        Element elEncryptedData = document.createElement("EncryptedData");
        
        elEncryptedData.setAttribute("xmlns", "http://www.exampleorg/xmlenc");
        
        // Append the <DecryptionInfo> child.
        elEncryptedData.appendChild(elDecryptionInfo);

        // Append the <CipherText> child holding the encrypted data.
        Element elCipherText = document.createElement("CipherText");
        
        elCipherText.appendChild(txtBase64EncodedElement);
        
        elEncryptedData.appendChild(elCipherText);
        
      
        if (boolContentOnly) {
            
            while (element.hasChildNodes()) {
                element.removeChild(element.getChildNodes().item(0));
            }
        
            element.appendChild((Node) elEncryptedData);

        } 
        else {
          
            Node nParentNode = element.getParentNode();
        
            nParentNode.replaceChild(elEncryptedData, element);
           
        }
               
        return;
    }
 // Encrypt an attribute value.
    public static void encryptAttributeValue(Attr attribute) {

        // Get the value of the attribute.
        String string = attribute.getValue();
        
        byte[] bytesToBeEncrypted = string.getBytes();
        byte[] bytesCiphertext = null;
        try {
            Cipher cipherDes = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipherDes.init(Cipher.ENCRYPT_MODE, secretKeyDesKey);

            bytesCiphertext = cipherDes.doFinal(bytesToBeEncrypted);   
        } catch (Exception ex) {
            System.out.println("Exception:");
            ex.printStackTrace();
        }        
        
        // Base64 encode the encrypted result.
        String base64EncodedAttribute = base64Encode(bytesCiphertext);
        
        // Replace the plaintext value of the attribute with the ciphertext.
        attribute.setValue(base64EncodedAttribute);
        Element elParent = attribute.getOwnerElement();

        if (!elParent.hasAttribute("enc:EncryptedDataManifest")) {
            elParent.setAttribute(
                    "enc:EncryptedDataManifest", 
                    "./EncryptedDataManifest");
            elParent.setAttribute(
                    "xmlns:enc", 
                    "http://www.example.org/xmlenc");
        }
        Element elEncryptedData = document.createElement("EncryptedData");

        elEncryptedData.setAttribute("Type", "AttributeValue");
        elEncryptedData.setAttribute("Name", attribute.getName());
        
        // Set up the <DecryptionInfo> element and append it.
        Element elDecryptionInfo = document.createElement("DecryptionInfo");        
        
        setupDecryptionInfo(elDecryptionInfo, secretKeyDesKey);
               
        elEncryptedData.appendChild(elDecryptionInfo);
        NodeList nlEncryptedDataManifest = elParent.getElementsByTagName("EncryptedDataManifest");

        if (nlEncryptedDataManifest.getLength() == 0) {
            Element elEncryptedDataManifest = document.createElement("EncryptedDataManifest");
        
            elEncryptedDataManifest.setAttribute("xmlns", "http://www.exampleorg/xmlenc");
        
            elEncryptedDataManifest.appendChild(elEncryptedData);
        
            elParent.insertBefore(
                    (Node) elEncryptedDataManifest,
                    elParent.getFirstChild());
        } else {
            
            Element elEncryptedDataManifest = (Element) nlEncryptedDataManifest.item(0);
            
            elEncryptedDataManifest.appendChild(elEncryptedData);            
        }
        return;
    }
 // Set up the <DecryptionInfo> element.
    private static void setupDecryptionInfo(Element elDecryptionInfo, SecretKey secretKey) {
        
        Element elDecryptionMethod = document.createElement("Method");
        elDecryptionInfo.appendChild(elDecryptionMethod);

        Element elDecryptionPropertyList = document.createElement("PropertyList");
        elDecryptionInfo.appendChild(elDecryptionPropertyList);        

        Element elDecryptionKey = document.createElement("Key");
        elDecryptionInfo.appendChild(elDecryptionKey);
        
        
        // My original goal was to illustrate a variety of <DecryptionInfo> elements so I set
        // a control counter.  However, for now we'll just use the raw symmetric key the whole
        // time.  Consequently, iDecryptionInfoCounter will always be zero.
        //
        // Note: The author recognizes that simply specifying the raw decryption key is useless 
        // from a security perspective, but the focus of this demo is illustrating how to encrypt
        // various types of XML nodes, not proper key management.
        if (iDecryptionInfoCounter > 0) {
            iDecryptionInfoCounter = 0;
        }
        
        switch (iDecryptionInfoCounter) {
            
            case 0:
                elDecryptionMethod.setAttribute("Algorithm", "http://www.example.org/xmlenc/des");         
                
                Element elValue = document.createElement("Value");
                elDecryptionKey.appendChild(elValue);              

                String base64EncodedKeyBytes = null;
                
                try {
                    DESKeySpec desKeySpec = (DESKeySpec) SecretKeyFactory.getInstance("DES").getKeySpec(secretKey, DESKeySpec.class);
                    base64EncodedKeyBytes = base64Encode(desKeySpec.getKey());            
                } catch(Exception ex) {
                    ex.printStackTrace();
                }

                Text txtBase64EncodedKeyBytes = document.createTextNode(base64EncodedKeyBytes);
                elValue.appendChild(txtBase64EncodedKeyBytes);                
                
                break;
            
            case 1:
                // Not finished!!!
                elDecryptionMethod.setAttribute("Algorithm", "http://www.example.org/xmlenc/rsa");         
                
                Element elPublicKeyData = document.createElement("PublicKeyData");
                elDecryptionKey.appendChild(elPublicKeyData);       
                
                Element elX509Data = document.createElement("X509Data");
                elPublicKeyData.appendChild(elX509Data);                
                break;
        }
        
        iDecryptionInfoCounter++;
    }
    /*
    Returns an element as a string.
*/

private static String getElementAsString(Element el, boolean boolContentOnly) {
	
	StringBuffer strbuf = new StringBuffer();

	if (!boolContentOnly) {
		strbuf.append("<" + el.getTagName());

		NamedNodeMap attrs = el.getAttributes();
							
		for (int i=0; i < attrs.getLength(); i++) {
			
			Node node = attrs.item(i);
			
			strbuf.append(" " + node.getNodeName() + "=\"" + node.getNodeValue() + "\"");
		}
	
		strbuf.append(">");
	}
	
	NodeList nl = el.getChildNodes();

	for (int i=0; i < nl.getLength(); i++) {
		
		Node node = nl.item(i);
		
		if (node.getNodeType() == Node.ELEMENT_NODE) {
			
			Element elChild = (Element) node;
			
			strbuf.append(getElementAsString(elChild, false));
		}

		if (node.getNodeType() == Node.TEXT_NODE) {
			
			strbuf.append(node.getNodeValue());
		}

		if (node.getNodeType() == Node.CDATA_SECTION_NODE) {
			
			strbuf.append("<![CDATA[");
			
			strbuf.append(node.getNodeValue());
			
			strbuf.append("]]>");
		}			
		
		if (node.getNodeType() == Node.ENTITY_REFERENCE_NODE) {
			
			strbuf.append("&");
			
			strbuf.append(node.getNodeValue());
			
			strbuf.append(";");
		}
	}

	if (!boolContentOnly) {
		strbuf.append("</" + el.getTagName() + ">");
	}
	
	return strbuf.toString().trim();
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

}

