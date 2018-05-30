/*
# These sample codes are provided for information purposes only. It does not imply any recommendation or endorsement by anyone.
  These sample codes are provided for FREE, and no additional support will be provided for these sample pages. 
  There is no warranty and no additional document. USE AT YOUR OWN RISK.
*/

package com.msctg.signet.fpx;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.StringTokenizer;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang3.StringEscapeUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemReader;

import model.bean.FPX;
import util.connection.DBConnection;
import util.general.Logger;
import util.property.SystemProperty;
import util.property.custom.CLogsProperty;

public class FpxController {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	static String errorCode="ErrorCode : [03]";
	static int cerExpiryCount=0;
	
	public static void main(String arg[]) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, CertificateException, NumberFormatException, ParseException {
		  String key_path = "C:\\jakarta-tomcat\\webapps\\mpay\\user\\reload\\fpx\\EXcert.cer";
		  /*InputStream inStream = new FileInputStream(key_path);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inStream);
			inStream.close();*/
			
			int year= Integer.parseInt(new SimpleDateFormat("yyyy").format(new Date()));	
			ArrayList<String> certFiles=new ArrayList<String>();
			//certFiles.add(path+File.separator+"fpx_current.cer");//Old Certificate 
			//certFiles.add(path+File.separator+"fpx.cer");		//New Certificate  
			certFiles.add(key_path);
			ArrayList<PublicKey> publicKeys=null;
			
			for(String file:certFiles)
			{
				publicKeys=checkCertExpiry(file);
				System.out.println(file+"<--->"+publicKeys.size());
				if(publicKeys.size()>0)
					System.out.println(publicKeys);
			}
		  
			ArrayList<PublicKey> pubKeys =publicKeys;
			for(PublicKey pubKey:pubKeys)
			{
				
			}
			if(pubKeys.size()==0) {	
				System.out.println("i am going crazy");
			}
		  /*String fpx_checkSum = "test123|001";
		  try {
			String final_checkSum = signData(key_path,fpx_checkSum,"SHA1withRSA");
			System.out.print(final_checkSum);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		  
		 }

	public static String signData(String pvtKeyFileName, String dataToSign,
			String signatureAlg) throws Exception 
	{

		PrivateKey privateKey = getPrivateKey(pvtKeyFileName);
		Signature signature = Signature.getInstance(signatureAlg, "BC");
		signature.initSign(privateKey);

		signature.update(dataToSign.getBytes());
		byte[] signatureBytes = signature.sign();

		return byteArrayToHexString(signatureBytes);

	}

	public static String verifyData(String pubKeyFileName,
			String calcCheckSum, String checkSumFromMsg,
			String signatureAlg) throws NoSuchAlgorithmException,
			NoSuchProviderException, IOException, InvalidKeySpecException,
			InvalidKeyException, SignatureException, CertificateException, NumberFormatException, ParseException 
	{
		
		boolean result=false;
		try
		{
			ArrayList<PublicKey> pubKeys = getFPXPublicKey(pubKeyFileName);
			Signature verifier = Signature.getInstance(signatureAlg, "BC");
			for(PublicKey pubKey:pubKeys)
			{
				verifier.initVerify(pubKey);
				//verifier.update(calcCheckSum.getBytes());
				verifier.update(StringEscapeUtils.unescapeHtml4(calcCheckSum).getBytes());
				result=verifier.verify(HexStringToByteArray(checkSumFromMsg));
				System.out.println("result ["+result+"]");
				if(result)
					return "00";
				else 
			      	return "Your Data cannot be verified against the Signature. ErrorCode :[09]";
			}
			
			if(pubKeys.size()==0 && cerExpiryCount ==1 ) {	
				return "One Certificate Found and Expired. ErrorCode : [07]";
			}
			else if(pubKeys.size()==0 && cerExpiryCount ==2 ) {
				return "Both Certificates Expired . ErrorCode : [08]";
			}
			if(pubKeys.size()==0) {	
				Logger.writeError("pubKeys size =="+ pubKeys.size(), CLogsProperty.GENERALLOG);
				return "Invalid Certificates. ErrorCode : [06]";
			}
		}
		catch(Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			Logger.writeError("FPXController: verifyData() "+ sw.toString(), CLogsProperty.GENERALLOG);
			return "ErrorCode : [03]"+e.getMessage();
		}
		finally {
			cerExpiryCount=0;
		}	
		return errorCode;
	}

	private static PublicKey getPublicKey(X509Certificate X509Cert)
	{
		return (RSAPublicKey) X509Cert.getPublicKey();
	}
	
	/*private static PrivateKey getPrivateKey(String pvtKeyFileName)
			throws IOException, Exception
	{
		FileReader pvtFileReader = getPVTKeyFile(new File(pvtKeyFileName));
		PemReader pvtPemReader = new PEMParser(pvtFileReader);
		PemObject obj = pvtPemReader.readPemObject();
		ASN1InputStream asnIn = new ASN1InputStream(obj.getContent());
        ASN1Primitive ao = asnIn.readObject();
        
        ASN1Sequence seq = (ASN1Sequence)ao;
        
        DERInteger p = (DERInteger)seq.getObjectAt(1);
        DERInteger q = (DERInteger)seq.getObjectAt(2);
        DERInteger g = (DERInteger)seq.getObjectAt(3);
        DERInteger y = (DERInteger)seq.getObjectAt(4);
        DERInteger x = (DERInteger)seq.getObjectAt(5);
        
        KeyFactory factory = KeyFactory.getInstance("DSA");
        
        DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(
                y.getValue(),
                p.getValue(),
                q.getValue(),
                g.getValue());
            PublicKey pub = factory.generatePublic(pubSpec);

            DSAPrivateKeySpec keySpec = new DSAPrivateKeySpec(
                x.getValue(),
                p.getValue(),
                q.getValue(),
                g.getValue());
            PrivateKey key = factory.generatePrivate(keySpec);
        
		KeyPair keyPair = new KeyPair(pub, key);

		pvtFileReader.close();
		pvtFileReader = null;
		pvtPemReader.close();
		pvtPemReader = null;
		return keyPair.getPrivate();
	}*/
	
	private static PrivateKey getPrivateKey(String pvtKeyFileName)throws IOException {
		FileReader pvtFileReader = getPVTKeyFile(new File(pvtKeyFileName));
		PEMParser pvtPemReader = new PEMParser(pvtFileReader);
		Object object = pvtPemReader.readObject();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		PrivateKey keyPair = converter.getPrivateKey((PrivateKeyInfo) object);
		pvtFileReader.close();
		pvtFileReader = null;
		pvtPemReader.close();
		pvtPemReader = null;
		return keyPair;
	}

	/*private static PrivateKey getPrivateKey(String pvtKeyFileName)throws IOException {
		FileReader pvtFileReader = getPVTKeyFile(new File(pvtKeyFileName));
//		PEMReader pvtPemReader = getPvtPemReader(pvtFileReader);
		PEMParser pvtPemReader = new PEMParser(pvtFileReader);
		KeyPair keyPair = (KeyPair) pvtPemReader.readObject();
		pvtFileReader.close();
		pvtFileReader = null;
		pvtPemReader.close();
		pvtPemReader = null;
		return keyPair.getPrivate();
	}*/

	private static FileReader getPVTKeyFile(File pvtFile) {
		FileReader pvtFileReader = null;
		try {
			pvtFileReader = new FileReader(pvtFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			pvtFileReader = null;
		}
		return pvtFileReader;
	}

//	private static PEMReader getPvtPemReader(Reader pvtFile) {
//		return new PEMReader(pvtFile);
//	}

	static char[] hexChar = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'A', 'B', 'C', 'D', 'E', 'F' };

	public static String byteArrayToHexString(byte b[]) {
		StringBuffer sb = new StringBuffer(b.length * 2);
		for (int i = 0; i < b.length; i++) {
			sb.append(hexChar[(b[i] & 0xf0) >>> 4]);
			sb.append(hexChar[b[i] & 0x0f]);
		}
		return sb.toString();
	}

	public static byte[] HexStringToByteArray(String strHex) {
		byte bytKey[] = new byte[(strHex.length() / 2)];
		int y = 0;
		String strbyte;
		for (int x = 0; x < bytKey.length; x++) {
			strbyte = strHex.substring(y, (y + 2));
			if (strbyte.equals("FF")) {
				bytKey[x] = (byte) 0xFF;
			} else {
				bytKey[x] = (byte) Integer.parseInt(strbyte, 16);
			}
			y = y + 2;
		}
		return bytKey;
	}
	
	private static X509Certificate getX509Certificate(String pubKeyFileName)throws CertificateException, IOException {
		InputStream inStream = new FileInputStream(pubKeyFileName);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inStream);
		inStream.close();
		return cert;
	}
	
	private static ArrayList<PublicKey> getFPXPublicKey(String path) throws CertificateException, IOException, NumberFormatException, ParseException
	{		
		int year= Integer.parseInt(new SimpleDateFormat("yyyy").format(new Date()));	
		ArrayList<String> certFiles=new ArrayList<String>();
		//certFiles.add(path+File.separator+"fpx_current.cer");//Old Certificate 
		//certFiles.add(path+File.separator+"fpx.cer");		//New Certificate  
		certFiles.add(path);
		ArrayList<PublicKey> publicKeys=null;
		
		for(String file:certFiles)
		{
			publicKeys=checkCertExpiry(file);
			System.out.println(file+"<--->"+publicKeys.size());
			if(publicKeys.size()>0)
				return publicKeys;
		}
		
		return publicKeys;
	}
	
	private static ArrayList<PublicKey> checkCertExpiry(String file) throws NumberFormatException, CertificateException, IOException, ParseException
	{
		ArrayList<PublicKey> publicKey=new ArrayList<PublicKey>();
		X509Certificate x509Cert=null; 
		SimpleDateFormat sdf=new SimpleDateFormat("dd-MMM-yyyy");
				int renamestatus;
		try{
			x509Cert=getX509Certificate(file);
		}
		catch(FileNotFoundException e) 
		{
			System.out.println("*****"+e);
			return publicKey;
		}
		
		Calendar currentDate=Calendar.getInstance();
		currentDate.setTime(sdf.parse(sdf.format(new Date())));

		
		Calendar certExpiryDate=Calendar.getInstance();
		certExpiryDate.setTime(sdf.parse(sdf.format(x509Cert.getNotAfter())));
		certExpiryDate.add(Calendar.DAY_OF_MONTH,-1);
		
		SimpleDateFormat settleSdf=new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss.SSS");
		
		System.out.println(settleSdf.format(certExpiryDate.getTime())+"<-->"+settleSdf.format(currentDate.getTime()));
		System.out.println(certExpiryDate.getTime()+"<-->"+currentDate.getTime()+"<->"+certExpiryDate.compareTo(currentDate));
				
		
		if(certExpiryDate.compareTo(currentDate)==0) //cert expiry and current date is same day so check is both cert
		{
			System.out.println("Same day do check with both cert");
			String nextFile=getNextCertFile(file);
			File nextFileCheck=new File(nextFile);

			if(!file.contains("fpx_current.cer") &&  nextFileCheck.exists())
			{
				renamestatus=certRollOver(nextFile);
				System.out.println("renstatus ["+renamestatus+"]");

			}
			System.out.println("cert1 ["+nextFile+"] cert2["+file+"]");
			if(nextFileCheck.exists())
			  publicKey.add(getPublicKey(getX509Certificate(nextFile)));
			
			publicKey.add(getPublicKey(x509Cert));
			
		}else if(certExpiryDate.compareTo(currentDate)==1) //Not Expired(Still valid) 
		{
			 if(file.contains("fpx.cer"))
			   {
				
				 renamestatus=certRollOver(file);
				System.out.println("renstatus ["+renamestatus+"]");

			    }
				
			System.out.println("Still valid  ["+file+"]");
						publicKey.add(getPublicKey(x509Cert));
		}
		else if(certExpiryDate.compareTo(currentDate)==-1) //Expired
		{
			
			cerExpiryCount=cerExpiryCount+1;

			System.out.println("Expired ["+file+"]");
		}
		
		
		return publicKey;
				
	}
	private static int certRollOver(String file) throws NumberFormatException, IOException
	{
		File old_crt=new File(file);

		File new_crt=new File(old_crt.getParent()+"\\fpx_current.cer");
		String timestamp = new java.text.SimpleDateFormat("yyyyMMddhmmss").format(new Date());

	    File newfile =new File(old_crt.getParent()+"\\fpx_current.cer"+timestamp);

		if(new_crt.exists() )
		{	
			//FPX_CURRENT.cer to FPX_CURRENT.cer_<CURRENT TIMESTAMP>
			System.out.println(new_crt+"old_crt is"+newfile);
			if(new_crt.renameTo(newfile)) {
	            System.out.println("File renamed");
			}
			else {
	            System.out.println("Sorry! the file can't be renamed");
	            return 01;
			}
		}
		
		if(!new_crt.exists() && old_crt.exists())
		{
			//FPX.cer to FPX_CURRENT.cer
			System.out.println(new_crt+"old_cer is"+old_crt);
			if(old_crt.renameTo(new_crt)){
				System.out.println("File renamed");
			}
			else {
	            System.out.println("Sorry! the file can't be renamed");
	            return 01;
	        }
		}
		return 00;
	}
	
	private static String getNextCertFile(String strFile) throws NumberFormatException, IOException
	{
		File file=new File(strFile);
		String fileName=file.getName();
		String strYear=fileName.substring(fileName.lastIndexOf(".")-4,fileName.lastIndexOf("."));
		return file.getParentFile()+File.separator+"fpx.cer";		
	}
	
	public static FPX calCheckSum(FPX ft) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException
	{
		//use key
		try{
			String fpx_checkSum = ft.getFpx_buyerAccNo()+"|"+ft.getFpx_buyerBankBranch()+"|"+ft.getFpx_buyerBankId()+"|"+ft.getFpx_buyerEmail()+"|"+ft.getFpx_buyerIban()+"|"+ft.getFpx_buyerId()+"|"+ft.getFpx_buyerName()+"|";
			fpx_checkSum += ft.getFpx_makerName()+"|"+ft.getFpx_msgToken()+"|"+ft.getFpx_msgType()+"|"+ft.getFpx_productDesc()+"|"+ft.getFpx_sellerBankCode()+"|"+ft.getFpx_sellerExId()+"|";
			fpx_checkSum += ft.getFpx_sellerExOrderNo()+"|"+ft.getFpx_sellerId()+"|"+ft.getFpx_sellerOrderNo()+"|"+ft.getFpx_sellerTxnTime()+"|"+ft.getFpx_txnAmount()+"|"+ft.getFpx_txnCurrency()+"|"+ft.getFpx_version();
			ft.setFpx_checkSum(fpx_checkSum);
			ft.setFinal_checkSum(FpxController.signData(SystemProperty.FPX_KEY, fpx_checkSum, "SHA1withRSA"));
		} catch (Exception e) {
			e.printStackTrace();
			Logger.writeActivity("FpxController:calCheckSum():"+e.toString(), CLogsProperty.ADMINGENERALLOG);
		}
		return ft;
	}
	
	public static String verifyCheckSum(FPX ft) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException
	{
		//use cert
		String pki_verification = "";
		try{
			String fpx_checkSum = ft.getFpx_buyerBankBranch()+"|"+ft.getFpx_buyerBankId()+"|"+ft.getFpx_buyerIban()+"|"+ft.getFpx_buyerId()+"|"+ft.getFpx_buyerName()+"|"+ft.getFpx_creditAuthCode()+"|"+ft.getFpx_creditAuthNo()+"|";
			fpx_checkSum += ft.getFpx_debitAuthCode()+"|"+ft.getFpx_debitAuthNo()+"|"+ft.getFpx_fpxTxnId()+"|"+ft.getFpx_fpxTxnTime()+"|"+ft.getFpx_makerName()+"|"+ft.getFpx_msgToken()+"|"+ft.getFpx_msgType()+"|";
			fpx_checkSum += ft.getFpx_sellerExId()+"|"+ft.getFpx_sellerExOrderNo()+"|"+ft.getFpx_sellerId()+"|"+ft.getFpx_sellerOrderNo()+"|"+ft.getFpx_sellerTxnTime()+"|"+ft.getFpx_txnAmount()+"|"+ft.getFpx_txnCurrency();
			
			pki_verification = FpxController.verifyData(SystemProperty.FPX_CERT, fpx_checkSum, ft.getFpx_checkSum(), "SHA1withRSA");
		} catch (Exception e) {
			e.printStackTrace();
			Logger.writeError("FpxController:verifyCheckSum():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
		}
		return pki_verification;
	}
	
	public static HashMap<String,String> requestTrxStatus(FPX ft) {
		HashMap<String,String> respMap = new HashMap<String,String>();
		try{
			StringBuilder postDataStrBuilder = new StringBuilder();
			postDataStrBuilder.append("fpx_msgType="+URLEncoder.encode(ft.getFpx_msgType(),"UTF-8"));
			postDataStrBuilder.append("&fpx_msgToken="+URLEncoder.encode(ft.getFpx_msgToken(),"UTF-8"));
			postDataStrBuilder.append("&fpx_sellerExId="+URLEncoder.encode(ft.getFpx_sellerExId(),"UTF-8"));
			postDataStrBuilder.append("&fpx_sellerExOrderNo="+URLEncoder.encode(ft.getFpx_sellerExOrderNo(),"UTF-8"));
			postDataStrBuilder.append("&fpx_sellerTxnTime="+URLEncoder.encode(ft.getFpx_sellerTxnTime(),"UTF-8"));
			postDataStrBuilder.append("&fpx_sellerOrderNo="+URLEncoder.encode(ft.getFpx_sellerOrderNo(),"UTF-8"));
			postDataStrBuilder.append("&fpx_sellerId="+URLEncoder.encode(ft.getFpx_sellerId(),"UTF-8"));
			postDataStrBuilder.append("&fpx_sellerBankCode="+URLEncoder.encode(ft.getFpx_sellerBankCode(),"UTF-8"));
			postDataStrBuilder.append("&fpx_txnCurrency="+URLEncoder.encode(ft.getFpx_txnCurrency(),"UTF-8"));
			postDataStrBuilder.append("&fpx_txnAmount="+URLEncoder.encode(ft.getFpx_txnAmount(),"UTF-8"));
			postDataStrBuilder.append("&fpx_buyerEmail="+URLEncoder.encode(ft.getFpx_buyerEmail(),"UTF-8"));
			postDataStrBuilder.append("&fpx_buyerName="+URLEncoder.encode(ft.getFpx_buyerName(),"UTF-8"));
			postDataStrBuilder.append("&fpx_buyerBankId="+URLEncoder.encode(ft.getFpx_buyerBankId(),"UTF-8"));
			postDataStrBuilder.append("&fpx_buyerBankBranch="+URLEncoder.encode(ft.getFpx_buyerBankBranch(),"UTF-8"));
			postDataStrBuilder.append("&fpx_buyerAccNo="+URLEncoder.encode(ft.getFpx_buyerAccNo(),"UTF-8"));
			postDataStrBuilder.append("&fpx_buyerId="+URLEncoder.encode(ft.getFpx_buyerId(),"UTF-8"));
			postDataStrBuilder.append("&fpx_makerName="+URLEncoder.encode(ft.getFpx_makerName(),"UTF-8"));
			postDataStrBuilder.append("&fpx_buyerIban="+URLEncoder.encode(ft.getFpx_buyerIban(),"UTF-8"));
			postDataStrBuilder.append("&fpx_productDesc="+URLEncoder.encode(ft.getFpx_productDesc(),"UTF-8"));
			postDataStrBuilder.append("&fpx_version="+URLEncoder.encode(ft.getFpx_version(),"UTF-8"));
			postDataStrBuilder.append("&fpx_checkSum="+URLEncoder.encode(ft.getFinal_checkSum(),"UTF-8"));
			
			// Create a trust manager that does not validate certificate chains only for testing environment
		    TrustManager[] trustAllCerts = new TrustManager[]
			{
				new X509TrustManager() 
				{
					public java.security.cert.X509Certificate[] getAcceptedIssuers() {
						return null;
					}
					public void checkClientTrusted(
						java.security.cert.X509Certificate[] certs, String authType) {
					}
					public void checkServerTrusted(
						java.security.cert.X509Certificate[] certs, String authType) {
					}
					public boolean isServerTrusted(java.security.cert.X509Certificate[] chain)
					{
						return true;
					}
					public boolean isClientTrusted(java.security.cert.X509Certificate[] chain)
					{
						return true;
					}
				}
			};
		
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() 
			{   public boolean verify(String hostname, SSLSession session) {return true;}
				public boolean verify(String hostname, String session) {return true;}
			});
				
			URLConnection conn = (HttpsURLConnection) new URL("https://uat.mepsfpx.com.my/FPXMain/sellerNVPReceiver.jsp").openConnection();
			conn.setDoOutput(true);
			
			BufferedWriter outputWriter=new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));	
			outputWriter.write(postDataStrBuilder.toString(),0,postDataStrBuilder.toString().length());			
			outputWriter.flush();
			outputWriter.close();
			
			BufferedReader inputReader=new BufferedReader(new InputStreamReader(conn.getInputStream()));		    
			String strResponse=null;
			
			while ((strResponse = inputReader.readLine())!=null) {
				System.out.println("Response is .."+strResponse);
				if(strResponse.length() > 0)
					break;
			} 
			
			System.out.println("strResponse:["+strResponse+"] result:["+strResponse.trim()+"] "+(strResponse.trim()).equals("PROSESSING ERROR"));
			inputReader.close();
			
			if(strResponse!=null && strResponse.trim().equals("msgfromfpx= PROSESSING ERROR"))
			{
				//out.println("An error occurred!..Response["+strResponse+"]");
				//return;
			}
			else
			{	
				StringTokenizer strToknzr = new StringTokenizer(strResponse,"&");
				while(strToknzr.hasMoreElements())
				{
					String temp = strToknzr.nextToken();
					if(temp.contains("="))
					{
						String nvp[]=temp.split("=");
						String name=nvp[0];
						String value="";
						if(nvp.length==2)
							value=URLDecoder.decode(nvp[1],"UTF-8");
							respMap.put(name, value);
					}
					else
					{
						System.out.println("Parsing Error!"+temp);			
					}
				}
				System.out.println("response Map["+respMap+"]");
			}
			
			String fpx_checkSumString = respMap.get("fpx_buyerBankBranch")+"|"+respMap.get("fpx_buyerBankId")+"|"+respMap.get("fpx_buyerIban")+"|"+respMap.get("fpx_buyerId")+"|"+respMap.get("fpx_buyerName")+"|"+respMap.get("fpx_creditAuthCode");
			fpx_checkSumString += "|"+respMap.get("fpx_creditAuthNo")+"|"+respMap.get("fpx_debitAuthCode")+"|"+respMap.get("fpx_debitAuthNo")+"|"+respMap.get("fpx_fpxTxnId")+"|"+respMap.get("fpx_fpxTxnTime")+"|"+respMap.get("fpx_makerName");
			fpx_checkSumString += "|"+respMap.get("fpx_msgToken")+"|"+respMap.get("fpx_msgType")+"|"+respMap.get("fpx_sellerExId")+"|"+respMap.get("fpx_sellerExOrderNo")+"|"+respMap.get("fpx_sellerId")+"|"+respMap.get("fpx_sellerOrderNo")+"|"+respMap.get("fpx_sellerTxnTime")+"|"+respMap.get("fpx_txnAmount")+"|"+respMap.get("fpx_txnCurrency");
			System.out.println("fpx_checkSumString:"+fpx_checkSumString);
			System.out.println("fpx_checkSum:"+respMap.get("fpx_checkSum"));
			String pkivarification = FpxController.verifyData(SystemProperty.FPX_KEY, fpx_checkSumString, respMap.get("fpx_checkSum"), "SHA1withRSA");
			
			if(!pkivarification.equals("00")){
				respMap = null;
			}
			
		} catch (Exception e) {
			e.printStackTrace();
			Logger.writeError("FpxController:requestTrxStatus():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
		}
		return respMap;
	}
	
	public static String getResponseCodeDesc(Connection connDB, String response_code)
	{
		ResultSet rs = null;
		PreparedStatement stmt = null;
		String result = "";
		try {
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			
			String query = "SELECT description FROM FPX_ResponseCode WHERE response_code = ?";
			stmt = connDB.prepareStatement(query);
			stmt.setString(1, response_code.trim());
			rs = stmt.executeQuery();
			
			if(rs.next()){
				result = rs.getString("description");
			}

			stmt.close();stmt = null;
			rs.close();rs = null;
			
		} catch (Exception e) {
			e.printStackTrace();
			Logger.writeError("FpxController:getResponseCodeDesc():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
		}
		return result;
	}
	
	public static FPX getFpxParam(Connection connDB, FPX ft) 
	{
		PreparedStatement stmt = null;
		ResultSet rs = null;
		String query = "";
		try{
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			query = "SELECT msg_token, seller_ex_id, seller_id, seller_bank_code, currency, version, ar_url, ae_url FROM FPX_Parameter where id= ? ";
			stmt = connDB.prepareStatement(query);
			stmt.setString(1, "1");
			rs = stmt.executeQuery();
			
			if(rs.next()){
				ft.setFpx_msgToken(rs.getString("msg_token"));
				ft.setFpx_sellerExId(rs.getString("seller_ex_id"));
				ft.setFpx_sellerId(rs.getString("seller_id"));
				ft.setFpx_sellerBankCode(rs.getString("seller_bank_code"));
				ft.setFpx_txnCurrency(rs.getString("currency"));
				ft.setFpx_version(rs.getString("version"));
				if (ft.getFpx_msgType().equalsIgnoreCase("AE"))
				{
					ft.setUrl(rs.getString("ae_url"));
				}
				else
				{
					ft.setUrl(rs.getString("ar_url"));
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
			Logger.writeError("FpxController:getFpxParam():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
		}
		return ft;
	}
	
	public static FPX getTwoDomainFpxParam(Connection connDB, FPX ft) 
	{
		PreparedStatement stmt = null;
		ResultSet rs = null;
		String query = "";
		try{
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			query = "SELECT msg_token, seller_ex_id, seller_id, seller_bank_code, currency, version, ar_url, ae_url FROM FPX_Parameter where id= ? ";
			stmt = connDB.prepareStatement(query);
			stmt.setString(1, "2");
			rs = stmt.executeQuery();
			
			if(rs.next()){
				//ft.setFpx_msgToken(rs.getString("msg_token"));
				ft.setFpx_sellerExId(rs.getString("seller_ex_id"));
				ft.setFpx_sellerId(rs.getString("seller_id"));
				ft.setFpx_sellerBankCode(rs.getString("seller_bank_code"));
				ft.setFpx_txnCurrency(rs.getString("currency"));
				ft.setFpx_version(rs.getString("version"));
				if (ft.getFpx_msgType().equalsIgnoreCase("AE"))
				{
					ft.setUrl(rs.getString("ae_url"));
				}
				else
				{
					ft.setUrl(rs.getString("ar_url"));
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
			Logger.writeError("FpxController:getTwoDomainFpxParam():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
		}
		return ft;
	}
	
	public static String insertFpxReqParam(Connection connDB, FPX ft) 
	{
		PreparedStatement stmt = null;
		StringBuffer query = null;
		ResultSet rs = null;
		String result = "";
		try{
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			query = new StringBuffer("INSERT INTO FPX_RequestParam (msgToken, sellerExId, sellerExOrderNo, sellerTxnTime, sellerOrderNo, sellerId, sellerBankCode, txnCurrency, ")
							.append("txnAmount, buyerEmail, checkSum, buyerName, buyerBankId, buyerBankBranch, buyerAccNo, buyerId, makerName, buyerIban, productDesc, version, fpxSourceType , fpx_partnerID) ")
							.append("VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? , ?);SELECT SCOPE_IDENTITY();");
			stmt = connDB.prepareStatement(query.toString());
			stmt.setString(1, ft.getFpx_msgToken());
			stmt.setString(2, ft.getFpx_sellerExId());
			stmt.setString(3, ft.getFpx_sellerExOrderNo());
			stmt.setString(4, ft.getFpx_sellerTxnTime());
			stmt.setString(5, ft.getFpx_sellerOrderNo());
			stmt.setString(6, ft.getFpx_sellerId());
			stmt.setString(7, ft.getFpx_sellerBankCode());
			stmt.setString(8, ft.getFpx_txnCurrency());
			stmt.setString(9, ft.getFpx_txnAmount());
			stmt.setString(10, ft.getFpx_buyerEmail());
			stmt.setString(11, ft.getFinal_checkSum());
			stmt.setString(12, ft.getFpx_buyerName());
			stmt.setString(13, ft.getFpx_buyerBankId());
			stmt.setString(14, ft.getFpx_buyerBankBranch());
			stmt.setString(15, ft.getFpx_buyerAccNo());
			stmt.setString(16, ft.getFpx_buyerId());
			stmt.setString(17, ft.getFpx_makerName());
			stmt.setString(18, ft.getFpx_buyerIban());
			stmt.setString(19, ft.getFpx_productDesc());
			stmt.setString(20, ft.getFpx_version());
			stmt.setString(21, ft.getFpx_sourceType());
			stmt.setString(22, ft.getFpx_partnerID());
			/*System.out.println(ft.getFpx_msgToken());
			System.out.println(ft.getFpx_sellerExId());
			System.out.println(ft.getFpx_sellerExOrderNo());
			System.out.println(ft.getFpx_sellerTxnTime());
			System.out.println(ft.getFpx_sellerOrderNo());
			System.out.println(ft.getFpx_sellerId());
			System.out.println(ft.getFpx_sellerBankCode());
			System.out.println(ft.getFpx_txnCurrency());
			System.out.println(ft.getFpx_txnAmount());
			System.out.println(ft.getFpx_buyerEmail());
			System.out.println(ft.getFinal_checkSum());
			System.out.println(ft.getFpx_buyerName());
			System.out.println(ft.getFpx_buyerBankId());
			System.out.println(ft.getFpx_buyerBankBranch());
			System.out.println(ft.getFpx_buyerAccNo());
			System.out.println(ft.getFpx_buyerId());
			System.out.println(ft.getFpx_makerName());
			System.out.println(ft.getFpx_buyerIban());
			System.out.println(ft.getFpx_productDesc());*/
			rs = stmt.executeQuery();
			
			if (rs.next())
				result = rs.getString(1);
			
		} catch(Exception e) {
			e.printStackTrace();
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			Logger.writeError("FpxController:insertFpxReqParam():" + sw, CLogsProperty.MEMBERSHIPLOG );
		}
		return result;
	}
	
	public static boolean updateFpxReqParam(Connection connDB, FPX ft) 
	{
		PreparedStatement stmt = null;
		String query = null;
		boolean result = false;
		try{
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			query = "UPDATE FPX_RequestParam SET ";
			if (ft.getFpx_msgToken()!=null&&!ft.getFpx_msgToken().equals(""))
			{
				query = query + " msgToken = ?, ";
			}
			if (ft.getFpx_sellerExId()!=null&&!ft.getFpx_sellerExId().equals(""))
			{
				query = query + " sellerExId = ?, ";
			}
			if (ft.getFpx_sellerExOrderNo()!=null&&!ft.getFpx_sellerExOrderNo().equals(""))
			{
				query = query + " sellerExOrderNo = ?, ";
			}
			if (ft.getFpx_sellerTxnTime()!=null&&!ft.getFpx_sellerTxnTime().equals(""))
			{
				query = query + " sellerTxnTime = ?, ";
			}
			if (ft.getFpx_sellerOrderNo()!=null&&!ft.getFpx_sellerOrderNo().equals(""))
			{
				query = query + " sellerOrderNo = ?, ";
			}
			if (ft.getFpx_sellerId()!=null&&!ft.getFpx_sellerId().equals(""))
			{
				query = query + " sellerId = ?, ";
			}
			if (ft.getFpx_sellerBankCode()!=null&&!ft.getFpx_sellerBankCode().equals(""))
			{
				query = query + " sellerBankCode = ?, ";
			}
			if (ft.getFpx_txnCurrency()!=null&&!ft.getFpx_txnCurrency().equals(""))
			{
				query = query + " txnCurrency = ?, ";
			}
			
			if (ft.getFpx_txnAmount()!=null&&!ft.getFpx_txnAmount().equals(""))
			{
				query = query + " txnAmount = ?, ";
			}
			if (ft.getFpx_buyerEmail()!=null&&!ft.getFpx_buyerEmail().equals(""))
			{
				query = query + " buyerEmail = ?, ";
			}
			if (ft.getFinal_checkSum()!=null&&!ft.getFinal_checkSum().equals(""))
			{
				query = query + " checkSum = ?, ";
			}
			if (ft.getFpx_buyerName()!=null&&!ft.getFpx_buyerName().equals(""))
			{
				query = query + " buyerName = ?, ";
			}
			if (ft.getFpx_buyerBankId()!=null&&!ft.getFpx_buyerBankId().equals(""))
			{
				query = query + " buyerBankId = ?, ";
			}
			if (ft.getFpx_buyerBankBranch()!=null&&!ft.getFpx_buyerBankBranch().equals(""))
			{
				query = query + " buyerBankBranch = ?, ";
			}
			if (ft.getFpx_buyerAccNo()!=null&&!ft.getFpx_buyerAccNo().equals(""))
			{
				query = query + " buyerAccNo = ?, ";
			}
			if (ft.getFpx_buyerId()!=null&&!ft.getFpx_buyerId().equals(""))
			{
				query = query + " buyerId = ?, ";
			}
			if (ft.getFpx_makerName()!=null&&!ft.getFpx_makerName().equals(""))
			{
				query = query + " makerName = ?, ";
			}
			if (ft.getFpx_buyerIban()!=null&&!ft.getFpx_buyerIban().equals(""))
			{
				query = query + " buyerIban = ?, ";
			}
			if (ft.getFpx_productDesc()!=null&&!ft.getFpx_productDesc().equals(""))
			{
				query = query + " productDesc = ?, ";
			}
			if (ft.getFpx_version()!=null&&!ft.getFpx_version().equals(""))
			{
				query = query + " version = ?, ";
			}
			if (ft.getFpx_creditAuthCode()!=null&&!ft.getFpx_creditAuthCode().equals(""))
			{
				query = query + " creditAuthCode = ?, ";
			}
			if (ft.getFpx_creditAuthNo()!=null&&!ft.getFpx_creditAuthNo().equals(""))
			{
				query = query + " creditAuthNo = ?, ";
			}
			if (ft.getFpx_debitAuthCode()!=null&&!ft.getFpx_debitAuthCode().equals(""))
			{
				query = query + " debitAuthCode = ?, ";
			}
			if (ft.getFpx_debitAuthNo()!=null&&!ft.getFpx_debitAuthNo().equals(""))
			{
				query = query + " debitAuthNo = ?, ";
			}
			if (ft.getFpx_fpxTxnId()!=null&&!ft.getFpx_fpxTxnId().equals(""))
			{
				query = query + " fpxTxnId = ?, ";
			}
			if (ft.getFpx_fpxTxnTime()!=null&&!ft.getFpx_fpxTxnTime().equals(""))
			{
				query = query + " fpxTxnTime = ?, ";
			}
			if (ft.getFpx_sourceType()!=null&&!ft.getFpx_sourceType().equals(""))
			{
				query = query + " fpxSourceType = ? ";
			}
			query = query + " WHERE  sellerExOrderNo = ?";
			
			stmt = connDB.prepareStatement(query);
			int k = 1;
			if (ft.getFpx_msgToken()!=null&&!ft.getFpx_msgToken().equals(""))
			{
				stmt.setString(k, ft.getFpx_msgToken());
				k++;
			}
			if (ft.getFpx_sellerExId()!=null&&!ft.getFpx_sellerExId().equals(""))
			{
				stmt.setString(k, ft.getFpx_sellerExId());
				k++;
			}
			if (ft.getFpx_sellerExOrderNo()!=null&&!ft.getFpx_sellerExOrderNo().equals(""))
			{
				stmt.setString(k, ft.getFpx_sellerExOrderNo());
				k++;
			}
			if (ft.getFpx_sellerTxnTime()!=null&&!ft.getFpx_sellerTxnTime().equals(""))
			{
				stmt.setString(k, ft.getFpx_sellerTxnTime());
				k++;
			}
			if (ft.getFpx_sellerOrderNo()!=null&&!ft.getFpx_sellerOrderNo().equals(""))
			{
				stmt.setString(k, ft.getFpx_sellerOrderNo());
				k++;
			}
			if (ft.getFpx_sellerId()!=null&&!ft.getFpx_sellerId().equals(""))
			{
				stmt.setString(k, ft.getFpx_sellerId());
				k++;
			}
			if (ft.getFpx_sellerBankCode()!=null&&!ft.getFpx_sellerBankCode().equals(""))
			{
				stmt.setString(k, ft.getFpx_sellerBankCode());
				k++;
			}
			if (ft.getFpx_txnCurrency()!=null&&!ft.getFpx_txnCurrency().equals(""))
			{
				stmt.setString(k, ft.getFpx_txnCurrency());
				k++;
			}
			
			if (ft.getFpx_txnAmount()!=null&&!ft.getFpx_txnAmount().equals(""))
			{
				stmt.setString(k, ft.getFpx_txnAmount());
				k++;
			}
			if (ft.getFpx_buyerEmail()!=null&&!ft.getFpx_buyerEmail().equals(""))
			{
				stmt.setString(k, ft.getFpx_buyerEmail());
				k++;
			}
			if (ft.getFinal_checkSum()!=null&&!ft.getFinal_checkSum().equals(""))
			{
				stmt.setString(k, ft.getFinal_checkSum());
				k++;
			}
			if (ft.getFpx_buyerName()!=null&&!ft.getFpx_buyerName().equals(""))
			{
				stmt.setString(k, ft.getFpx_buyerName());
				k++;
			}
			if (ft.getFpx_buyerBankId()!=null&&!ft.getFpx_buyerBankId().equals(""))
			{
				stmt.setString(k, ft.getFpx_buyerBankId());
				k++;
			}
			if (ft.getFpx_buyerBankBranch()!=null&&!ft.getFpx_buyerBankBranch().equals(""))
			{
				stmt.setString(k, ft.getFpx_buyerBankBranch());
				k++;
			}
			if (ft.getFpx_buyerAccNo()!=null&&!ft.getFpx_buyerAccNo().equals(""))
			{
				stmt.setString(k, ft.getFpx_buyerAccNo());
				k++;
			}
			if (ft.getFpx_buyerId()!=null&&!ft.getFpx_buyerId().equals(""))
			{
				stmt.setString(k, ft.getFpx_buyerId());
				k++;
			}
			if (ft.getFpx_makerName()!=null&&!ft.getFpx_makerName().equals(""))
			{
				stmt.setString(k, ft.getFpx_makerName());
				k++;
			}
			if (ft.getFpx_buyerIban()!=null&&!ft.getFpx_buyerIban().equals(""))
			{
				stmt.setString(k, ft.getFpx_buyerIban());
				k++;
			}
			if (ft.getFpx_productDesc()!=null&&!ft.getFpx_productDesc().equals(""))
			{
				stmt.setString(k, ft.getFpx_productDesc());
				k++;
			}
			if (ft.getFpx_version()!=null&&!ft.getFpx_version().equals(""))
			{
				stmt.setString(k, ft.getFpx_version());
				k++;
			}
			
			if (ft.getFpx_creditAuthCode()!=null&&!ft.getFpx_creditAuthCode().equals(""))
			{
				stmt.setString(k, ft.getFpx_creditAuthCode());
				k++;
			}
			if (ft.getFpx_creditAuthNo()!=null&&!ft.getFpx_creditAuthNo().equals(""))
			{
				stmt.setString(k, ft.getFpx_creditAuthNo());
				k++;
			}
			if (ft.getFpx_debitAuthCode()!=null&&!ft.getFpx_debitAuthCode().equals(""))
			{
				stmt.setString(k, ft.getFpx_debitAuthCode());
				k++;
			}
			if (ft.getFpx_debitAuthNo()!=null&&!ft.getFpx_debitAuthNo().equals(""))
			{
				stmt.setString(k, ft.getFpx_debitAuthNo());
				k++;
			}
			if (ft.getFpx_fpxTxnId()!=null&&!ft.getFpx_fpxTxnId().equals(""))
			{
				stmt.setString(k, ft.getFpx_fpxTxnId());
				k++;
			}
			if (ft.getFpx_fpxTxnTime()!=null&&!ft.getFpx_fpxTxnTime().equals(""))
			{
				stmt.setString(k, ft.getFpx_fpxTxnTime());
				k++;
			}
			if (ft.getFpx_sourceType()!=null&&!ft.getFpx_sourceType().equals(""))
			{
				stmt.setString(k, ft.getFpx_sourceType());
				k++;
			}

			stmt.setString(k, ft.getFpx_sellerOrderNo());
			/*System.out.println(ft.getFpx_msgToken());
			System.out.println(ft.getFpx_sellerExId());
			System.out.println(ft.getFpx_sellerExOrderNo());
			System.out.println(ft.getFpx_sellerTxnTime());
			System.out.println(ft.getFpx_sellerOrderNo());
			System.out.println(ft.getFpx_sellerId());
			System.out.println(ft.getFpx_sellerBankCode());
			System.out.println(ft.getFpx_txnCurrency());
			System.out.println(ft.getFpx_txnAmount());
			System.out.println(ft.getFpx_buyerEmail());
			System.out.println(ft.getFinal_checkSum());
			System.out.println(ft.getFpx_buyerName());
			System.out.println(ft.getFpx_buyerBankId());
			System.out.println(ft.getFpx_buyerBankBranch());
			System.out.println(ft.getFpx_buyerAccNo());
			System.out.println(ft.getFpx_buyerId());
			System.out.println(ft.getFpx_makerName());
			System.out.println(ft.getFpx_buyerIban());
			System.out.println(ft.getFpx_productDesc());*/
			stmt.executeUpdate();
			result = true;
		} catch(Exception e) {
			e.printStackTrace();
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			Logger.writeError("FpxController:updateFpxReqParam():" + sw, CLogsProperty.MEMBERSHIPLOG );
		}
		return result;
	}
	
	public static FPX ThirdPartyGetFpxReqParam(Connection connDB, String trx_id, String PID) 
	{
		Logger.writeActivity("FpxController:ThirdPartyGetFpxReqParam()Started", CLogsProperty.ADMINMEMBERSHIPLOG );
		PreparedStatement stmt = null;
		ResultSet rs = null;
		String query = null;
		FPX ft = new FPX();
		try{
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			query = "SELECT * FROM FPX_RequestParam a INNER JOIN MasterTrx b ON a.sellerOrderNo = b.id INNER JOIN Account c ON b.account_no = c.account_no "
					+ " INNER JOIN AccountTypeLookup d ON c.accounttypelookup_id = d.id INNER JOIN ThirdPartyIntegrataionCompanyInfo e ON e.partnerID = a.fpx_partnerID"
					+ " INNER JOIN TrxDetailReloadAcc f ON b.trx_detail_id = f.id "
					+ " WHERE a.sellerOrderNo = ? AND e.partnerID = ? AND f.trxstatuslookup_id = 4 ";
			stmt = connDB.prepareStatement(query);
			stmt.setString(1, trx_id);
			stmt.setString(2, PID);
			rs = stmt.executeQuery();
			if(rs.next()) {
				Logger.writeActivity("FpxController:ThirdPartyGetFpxReqParam()successful", CLogsProperty.ADMINMEMBERSHIPLOG );
				ft.setFpx_msgType("AR");
				ft.setFpx_msgToken(rs.getString("msgToken"));
				ft.setFpx_sellerExId(rs.getString("sellerExId"));
				ft.setFpx_sellerExOrderNo(rs.getString("sellerExOrderNo"));
				ft.setFpx_sellerTxnTime(rs.getString("sellerTxnTime"));
				ft.setFpx_sellerOrderNo(rs.getString("sellerOrderNo"));
				ft.setFpx_sellerId(rs.getString("sellerId"));
				ft.setFpx_sellerBankCode(rs.getString("sellerBankCode"));
				ft.setFpx_txnCurrency(rs.getString("txnCurrency"));
				ft.setFpx_txnAmount(rs.getString("txnAmount"));
				ft.setFpx_buyerEmail(rs.getString("buyerEmail"));
				ft.setFinal_checkSum(rs.getString("checkSum"));
				ft.setFpx_buyerName(rs.getString("buyerName"));
				ft.setFpx_buyerBankId(rs.getString("buyerBankId"));
				ft.setFpx_buyerBankBranch(rs.getString("buyerBankBranch"));
				ft.setFpx_buyerAccNo(rs.getString("buyerAccNo"));
				ft.setFpx_buyerId(rs.getString("buyerId"));
				ft.setFpx_makerName(rs.getString("makerName"));
				ft.setFpx_buyerIban(rs.getString("buyerIban"));
				ft.setFpx_productDesc(rs.getString("productDesc"));
				ft.setFpx_version(rs.getString("version"));
				/*ft.setFpx_sourceType(rs.getString("fpxSourceType"));*/
				ft = FpxController.getFpxParam(connDB, ft);
				ft = FpxController.calCheckSum(ft);
				ft.setFpx_sourceType("0");
				ft.setFpx_partnerID(PID);
				/*ft = FpxController.calCheckSum(ft);*/
			}
			else
			{
				ft.setStatusDesc("xxx");
				Logger.writeActivity("FpxController:ThirdPartyGetFpxReqParam()failed", CLogsProperty.ADMINMEMBERSHIPLOG );
				
			}
		} catch(Exception e) {
			e.printStackTrace();
			Logger.writeError(e, "FpxController:ThirdPartyGetFpxReqParam():", CLogsProperty.ADMINMEMBERSHIPLOG );
			return ft;
		}
		return ft;
	}
	
	public static FPX getFpxReqParam(Connection connDB, String trx_id) 
	{
		PreparedStatement stmt = null;
		ResultSet rs = null;
		String query = null;
		FPX ft = new FPX();
		try{
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			query = "SELECT msgToken, sellerExId, sellerExOrderNo, sellerTxnTime, sellerOrderNo, sellerId, sellerBankCode, txnCurrency, txnAmount, buyerEmail, "+
					"checkSum, buyerName, buyerBankId, buyerBankBranch, buyerAccNo, buyerId, makerName, buyerIban, productDesc, version, fpxSourceType FROM FPX_RequestParam WHERE sellerOrderNo = ?";
			stmt = connDB.prepareStatement(query);
			stmt.setString(1, trx_id);
			rs = stmt.executeQuery();
			if(rs.next()) {
				
				ft.setFpx_msgType("AE");
				ft.setFpx_msgToken(rs.getString("msgToken"));
				ft.setFpx_sellerExId(rs.getString("sellerExId"));
				ft.setFpx_sellerExOrderNo(rs.getString("sellerExOrderNo"));
				ft.setFpx_sellerTxnTime(rs.getString("sellerTxnTime"));
				ft.setFpx_sellerOrderNo(rs.getString("sellerOrderNo"));
				ft.setFpx_sellerId(rs.getString("sellerId"));
				ft.setFpx_sellerBankCode(rs.getString("sellerBankCode"));
				ft.setFpx_txnCurrency(rs.getString("txnCurrency"));
				ft.setFpx_txnAmount(rs.getString("txnAmount"));
				ft.setFpx_buyerEmail(rs.getString("buyerEmail"));
				ft.setFinal_checkSum(rs.getString("checkSum"));
				ft.setFpx_buyerName(rs.getString("buyerName"));
				ft.setFpx_buyerBankId(rs.getString("buyerBankId"));
				ft.setFpx_buyerBankBranch(rs.getString("buyerBankBranch"));
				ft.setFpx_buyerAccNo(rs.getString("buyerAccNo"));
				ft.setFpx_buyerId(rs.getString("buyerId"));
				ft.setFpx_makerName(rs.getString("makerName"));
				ft.setFpx_buyerIban(rs.getString("buyerIban"));
				ft.setFpx_productDesc(rs.getString("productDesc"));
				ft.setFpx_version(rs.getString("version"));
				ft.setFpx_sourceType(rs.getString("fpxSourceType"));
			}
		} catch(Exception e) {
			e.printStackTrace();
			Logger.writeError("FpxController:getFpxReqParam():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
			return ft;
		}
		return ft;
	}
	
	public static FPX setFpxObject(HashMap<String, String> respMap) 
	{
		FPX ft = new FPX();
		try{
			ft.setFpx_msgType(respMap.get("fpx_msgType"));
			ft.setFpx_msgToken(respMap.get("fpx_msgToken"));
			ft.setFpx_sellerExId(respMap.get("fpx_sellerExId"));
			ft.setFpx_sellerExOrderNo(respMap.get("fpx_sellerExOrderNo"));
			ft.setFpx_sellerTxnTime(respMap.get("fpx_sellerTxnTime"));
			ft.setFpx_sellerOrderNo(respMap.get("fpx_sellerOrderNo"));
			ft.setFpx_sellerId(respMap.get("fpx_sellerId"));
			ft.setFpx_txnCurrency(respMap.get("fpx_txnCurrency"));
			ft.setFpx_txnAmount(respMap.get("fpx_txnAmount"));
			ft.setFpx_buyerName(respMap.get("fpx_buyerName"));
			ft.setFpx_buyerBankId(respMap.get("fpx_buyerBankId"));
			ft.setFpx_buyerBankBranch(respMap.get("fpx_buyerBankBranch"));
			ft.setFpx_buyerId(respMap.get("fpx_buyerId"));
			ft.setFpx_makerName(respMap.get("fpx_makerName"));
			ft.setFpx_buyerIban(respMap.get("fpx_buyerIban"));
			ft.setFpx_creditAuthNo(respMap.get("fpx_creditAuthNo"));
			ft.setFpx_creditAuthCode(respMap.get("fpx_creditAuthCode"));
			ft.setFpx_debitAuthNo(respMap.get("fpx_debitAuthNo"));
			ft.setFpx_debitAuthCode(respMap.get("fpx_debitAuthCode"));
			ft.setFpx_fpxTxnId(respMap.get("fpx_fpxTxnId"));
			ft.setFpx_fpxTxnTime(respMap.get("fpx_fpxTxnTime"));
			ft.setStatusDesc(getResponseCodeDesc(null, ft.getFpx_debitAuthCode()));
		} catch(Exception e) {
			e.printStackTrace();
			Logger.writeError("FpxController:setFpxObject():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
		}
		return ft;
	}
	
	public ArrayList getFpxBankList(Connection connDB, String fpx_msgToken)
	{
		PreparedStatement stmt = null;
		ResultSet rs = null;
		String query = null;
		ArrayList bankList = new ArrayList();
		
		try{
			if(connDB == null) {
				connDB = DBConnection.getConnection();
			}
			query = "SELECT bank_id, bank_display_name, status "+
					" FROM FPX_BankList WHERE fpx_msgToken = ? order by bank_display_name ";
			stmt = connDB.prepareStatement(query);
			stmt.setString(1, fpx_msgToken);
			rs = stmt.executeQuery();
			while (rs.next())	{
				bankList.add(rs.getString("bank_id"));
				bankList.add(rs.getString("bank_display_name"));
				bankList.add(rs.getString("status"));
			}
		} catch(Exception e) {
			e.printStackTrace();
			Logger.writeError("getFpxBankList():" + e.toString(), CLogsProperty.ADMINMEMBERSHIPLOG );
			return null;
		}
		return bankList;
	}
}