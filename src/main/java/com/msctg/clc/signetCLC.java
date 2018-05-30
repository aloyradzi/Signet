/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.msctg.clc;


import certManagement.CLCData;
import certManagement.ReadCSR;
import certManagement.deleteFile;
import certManagement.saveUserDet;
import certManagement.updateUserDet;
import certManagement.verifyOU;
import certManagement.x509;
import static certManagement.getUserDet.logger;
import static certManagement.saveUserDet.logger;
import com.verisign.pki.client.sampleclient.CertificateManagementServiceStub;
import com.verisign.pki.client.sampleclient.PolicyServiceStub;
import com.verisign.pki.client.sampleclient.SampleCertMgmtClient;
import com.verisign.pki.client.sampleclient.SampleEnrollmentServiceClient;
import static com.verisign.pki.client.sampleclient.SampleEnrollmentServiceClient.REQUEST_TYPE_ISSUE;
import static com.verisign.pki.client.sampleclient.SampleEnrollmentServiceClient.REQUEST_TYPE_RENEW;
import com.verisign.pki.client.sampleclient.SampleParameters;
import com.verisign.pki.client.sampleclient.SamplePolicyServiceClient;
import com.verisign.pki.client.sampleclient.VeriSignCertIssuingServiceStub;
import com.verisign.pki.client.sampleclient.parametersData;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import org.apache.axis2.AxisFault;
import org.apache.axis2.databinding.ADBException;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.openssl.PEMParser;
import verifyCAPayload.verifyCAPayload;

/**
 *
 * @author NB028-16
 */
@WebService(serviceName = "CLCWebservices")
public class signetCLC {

    String statusCode = null;
    String statusMsg = null;
    String PIN = "1234";   
    String certValidity = "365";
    int result;
    
    
    static Logger logger = Logger.getLogger(signetCLC.class.getName());
    
    /**
     * This is a sample web service operation
     */
    @WebMethod(operationName = "enroll")
    public CLCData Enroll(@WebParam(name = "CSR")String CSR, @WebParam(name = "OU")String OU)
    {
        
        CLCData returnData = new CLCData();
        parametersData param = new parametersData();
        String cnname=null;
        String locality=null;
        String jobTitle = null;
        String corp_company = null;
        String uid = null;
        
    //logger.info("[enroll] userid: " + icNumber+"-"+cnname);
            
    boolean stat_Valid=ValidateEnrollParam(CSR,OU);
    if(stat_Valid) {
        logger.info("[ValidateEnrollParam]validation TRUE = "+OU);
        logger.info("[ValidateEnrollParam]OU = "+OU);
        logger.info("[ValidateEnrollParam]csr = "+CSR);
        
    } else {
        
        returnData.setiErrorCode(statusCode); 
        logger.info("[ValidateEnrollParam] Parameter validation false");
        
        returnData.setsErrorMessage(statusMsg); 
        logger.info("[ValidateEnrollParam] Parameter validation false");

        return returnData;
    }
    
        //verifyOU
        try{
            
            verifyOU reads = new verifyOU();
            param = reads.readOU(OU);
        
                    logger.info("common_name: "+param.getCN());
                    logger.info("jobTitle: "+param.getTitle());
                    logger.info("mykad: "+param.getUid());
                    logger.info("mail_email: "+param.getEmail());
                    logger.info("locality: "+param.getLocality());
                    logger.info("state: "+param.getState());
                    logger.info("country: "+param.getCountry());
                    logger.info("corp_company: "+param.getCompany());
                    logger.info("serialnumber: "+param.getSerialnumber());
            
                    jobTitle = param.getTitle();
                    corp_company = param.getCompany();
                    uid = param.getUid();
                    
        }catch(Exception e){
            System.out.println("param Set 3: "+param.getStatusCSR());
            returnData.setiErrorCode("661");
            returnData.setsErrorMessage("Error: "+param.getStatusOU());
            return returnData;
        }
        System.out.println("param Set 4: "+param.getStatusCSR());
        if(param.getStatusCSR().equalsIgnoreCase("-1")||param.getStatusCSR().equalsIgnoreCase("-7")){
            
                returnData.setiErrorCode("661");
                returnData.setsErrorMessage("Error: "+param.getStatusOU());
                return returnData;
            
        }
        
        
        
    
    
        //readCSR    
        try {
    
            InputStream stream = new ByteArrayInputStream(CSR.getBytes(StandardCharsets.UTF_8));

            ReadCSR m = new ReadCSR();
            param = m.readCertificateSigningRequest(stream);
        }catch (Exception e){
                returnData.setiErrorCode("662");
                returnData.setsErrorMessage("Error: "+param.getErrorMsg());
                logger.error("ReadCSR error: "+e.getMessage());
                return returnData;
        }
  
        if(param.getStatusCSR().equalsIgnoreCase("0"))
        {
                    logger.info("uid------------------------"+uid);
            
                    HashMap <String,String> sampleInput = new HashMap<String,String>();
                    
                    sampleInput.put("common_name", param.getCN());
                    sampleInput.put("jobTitle", jobTitle);
                    //sampleInput.put("mykad", uid);
                    sampleInput.put("mail_email", param.getEmail());
                    sampleInput.put("locality", param.getLocality()); 
                    sampleInput.put("state", param.getState());
                    sampleInput.put("country", param.getCountry());
                    sampleInput.put("corp_company", corp_company);
                    sampleInput.put("publish_flag", "yes");
                    sampleInput.put("additional_field4", uid);


                    SampleParameters.sampleInput = sampleInput;
                    param.setCertFileName(param.getUid());
                    param.setPinCert(PIN);
                    param.setCertValidity(certValidity);
                    param.setCsr(CSR);
        }else{
            logger.error("readCSR error: "+param.getErrorMsg());
            returnData.setiErrorCode("662");
            returnData.setsErrorMessage("Exception: "+param.getErrorMsg());
            return returnData;
        }
     
            
                    logger.info("common_name222: "+param.getCN());
                    logger.info("jobTitle: "+jobTitle);
                    logger.info("mykad: "+uid);
                    logger.info("mail_email: "+param.getEmail());
                    logger.info("locality: "+param.getLocality());
                    logger.info("state: "+param.getState());
                    logger.info("country: "+param.getCountry());
                    logger.info("corp_company: "+corp_company);
                    
        
        boolean stat_getEnroll=false;
    
        try {
        
        int validityCert = Integer.parseInt(certValidity);
            
        //get enrollment policy
        SamplePolicyServiceClient samplePolicyServiceClient = SamplePolicyServiceClient.getInstance(param);
        //samplePolicyServiceClient.param = param;
        //use the first enrollment policy to enroll for a cert
        PolicyServiceStub.CertificateEnrollmentPolicy certificateEnrollmentPolicy = samplePolicyServiceClient.enrollmentPolices[0];
        
        //use SampleEnrollmentServiceClient to request for certificate
        SampleEnrollmentServiceClient sampleEnrollmentServiceClient = new SampleEnrollmentServiceClient(certificateEnrollmentPolicy,samplePolicyServiceClient.getOIDByReferenceID(certificateEnrollmentPolicy.getPolicyOIDReference()).getValue(),param.getSampleOutputPath() + "/" + param.getCertFileName(),param);
        VeriSignCertIssuingServiceStub.RequestSecurityTokenResponse requestSecurutyTokenResponse = sampleEnrollmentServiceClient.enrollForCertificate(REQUEST_TYPE_ISSUE.getValue(), null,validityCert,param);
        sampleEnrollmentServiceClient.processRequestSecurityTokenResponse(requestSecurutyTokenResponse,param);
        
        
        stat_getEnroll=true;
        } catch (CertificateException e) {
                e.printStackTrace();
                returnData.setiErrorCode("610");
                returnData.setsErrorMessage("Exception: Enrollment failed ");
                //logger.error("[Enroll] Enrollment failed with exception : "+e.printStackTrace(s));
                return returnData;
        } catch (NoSuchProviderException e) {
                e.printStackTrace();
                returnData.setiErrorCode("611");
                returnData.setsErrorMessage("Exception: Enrollment failed");
                //logger.error("[Enroll] Enrollment failed with exception : "+e.printStackTrace(s));
                return returnData;
        } catch (Throwable e) {
                e.printStackTrace();
                returnData.setiErrorCode("612");
                returnData.setsErrorMessage("Exception: Enrollment failed");
                //logger.error("[Enroll] Enrollment failed with exception : "+e.printStackTrace());
                return returnData;
        }
      
        if(stat_getEnroll) {
                
        x509 cx509 = new x509();
        boolean convertB64 = false;
        //add readconfig 
                    try {
                        //convert p7b base64 to x509 base64 get serialnumber and validity date
                        convertB64 = cx509.convertb64(param);
                    } catch (IOException ex) {
                        returnData.setiErrorCode("622");
                        returnData.setsErrorMessage("Exception: convert base64 p7b to x509 failed");
                        logger.error("[convertB64] convert base64 p7b to x509 failed : " + ex.getMessage());
                        return returnData;
                    }

                    if(convertB64) {
                        logger.info("[convertB64] convert base64 p7b to x509 success");

                    } else {
                        returnData.setiErrorCode("602");
                        logger.error("[convertB64] convert base64 p7b to x509 failed : ");

                    return returnData; //exit
                    }
                    
                    
            //save information to DB
            saveUserDet sUd = new saveUserDet();
            boolean update_db=sUd.saveUserDets(param.getCN(),uid,param.getBase64Cert(),param.getCertStartDate(),param.getCertEndDate(),param.getPinCert(),param.getCertSerial(),param.getIssuerDN());
            if(update_db)
            { 
               logger.info("[saveUserDet] save user details status : "+sUd.status_code+""+sUd.status_msg);
            } 
            else {
               returnData.setiErrorCode(sUd.status_code);
               returnData.setsErrorMessage(sUd.status_msg);
               logger.error("[saveUserDet] save user details failed : "+sUd.status_code+""+sUd.status_msg);
               return returnData; //exit
            }
                
            logger.info("[getEnroll] Enrollment success");
            returnData.setiErrorCode("000");
            returnData.setBase64(param.getBase64Cert());
            returnData.setCertSerialnumber(param.getCertSerial());
            returnData.setStartDate(param.getCertStartDate());
            returnData.setEndDate(param.getCertEndDate());
            returnData.setsErrorMessage("Enrollment success");
            
        } else {
            returnData.setiErrorCode("601");
            returnData.setsErrorMessage("Enrollment failed");  
            logger.error("[getEnroll] Enrollment failed : ");

           
        }  
    
       //System.out.println("password " +System.currentTimeMillis());
        
        deleteFile delete = new deleteFile();
        
        String p7b = param.getSampleOutputPath()+""+param.getCertFileName();
        String pass = param.getSampleOutputPath()+""+param.getCertFileName()+".p12.password";
        String response = param.getSampleOutputPath()+""+"Response.xml";
        
        System.out.println("p7b "+p7b);
        System.out.println("pass "+pass);
        System.out.println("response "+response);
        
        //delete file p7b
        //delete.deleteFile(p7b);
        //delete file password   
        //delete.deleteFile(pass);
        //delete Response.xml
        delete.deleteFile(response);
        
        return returnData;
    }
    
    
    
    
    
    
    //-----------------------ValidateEnrollParam----------------------------------------
    private boolean ValidateEnrollParam (String CSR, String OU) {
        
    boolean stat_Valid=true;
            
      try {
        String paramVal=null;
        String[] params = new String[] {"CSR","OU"};
          for (String prm:params) {
                            
              //get value 
              if (prm.equals("CSR")) {
                  paramVal=CSR;                            
              }  
              if (prm.equals("OU")) {
                  paramVal=OU;                            
              } 
              
             
                //validate 
                if(paramVal == null || paramVal.trim().length()==0) {
                    statusCode="600";
                    statusMsg="Missing parameter value for " + prm;
                    stat_Valid=false;
                    break;
                }
            }               
          
               
      } catch(Exception e){
          statusCode = "600";
          statusMsg = e.getMessage();
          return false;
      }
      
      //logger.info("[ValidateEnrollParam] Parameter recieve, USER ID "+icNumber+ "PIN" +cnname);
      return stat_Valid;
           
  }
    

 
    
 //-----------------------------renewall----------------------------------------------
    
        @WebMethod(operationName = "renewal")
    public CLCData Renewal(@WebParam(name = "CAPayload") String CAPayload, @WebParam(name = "CSR") String CSR,@WebParam(name = "Cert") String base64,@WebParam(name = "OU") String OU)
    {
        
        //String certRenew = null;
        
        CLCData returnData = new CLCData();
        parametersData param = new parametersData();
        

        
    boolean stat_Valid=ValidateRenewalParam(CAPayload, CSR, base64, OU);
    if(stat_Valid) {
        logger.info("[ValidateRenewalParam]Parameter validation true");
        
    } else {
        
        returnData.setiErrorCode(statusCode); 
        logger.info("[ValidateRenewalParam] Parameter validation false");
        
        returnData.setsErrorMessage(statusMsg); 
        logger.info("[ValidateRenewalParam] Parameter validation false");

        return returnData;
    }
    
    //verifyOU
        try{
            
            verifyOU read = new verifyOU();
            param = read.readOU(OU);
        
        }catch(Exception e){
            System.out.println("param Set 3: "+param.getStatusCSR());
            returnData.setiErrorCode("661");
            returnData.setsErrorMessage("Error: "+param.getStatusOU());
            return returnData;
        }
        System.out.println("param Set 4: "+param.getStatusCSR());
        if(param.getStatusCSR().equalsIgnoreCase("-1")||param.getStatusCSR().equalsIgnoreCase("-7")){
            
                returnData.setiErrorCode("661");
                returnData.setsErrorMessage("Error: "+param.getStatusOU());
                return returnData;
            
        }
    
    
    //verifyCAPayload
        try{
            
           verifyCAPayload verify = new verifyCAPayload(); 
           String type = "renewal";
           param = verify.varifyCAPayload(CAPayload,type,CSR);
        }catch(Exception e)
        { 

                returnData.setiErrorCode(param.getStatuscodePayload());
                returnData.setsErrorMessage("Error: "+param.getStatusPayload());
                logger.error("ReadCSR error: "+e.getMessage());
                logger.error("ReadCSR error: "+param.getStatusPayload());
                return returnData;
        }
    
        if(param.getStatuscodePayload().equalsIgnoreCase("-1")||param.getStatuscodePayload().equalsIgnoreCase("-7")){
            
                returnData.setiErrorCode("661");
                returnData.setsErrorMessage("Error: "+param.getStatusPayload());
                return returnData;
            
        }
        
        
           //readCSR    
        try {
    
            InputStream stream = new ByteArrayInputStream(CSR.getBytes(StandardCharsets.UTF_8));

            ReadCSR m = new ReadCSR();
            param = m.readCertificateSigningRequest(stream);
        }catch (Exception e){
                returnData.setiErrorCode("662");
                returnData.setsErrorMessage("Error: "+param.getErrorMsg());
                logger.error("ReadCSR error: "+e.getMessage());
                return returnData;
        }
  
        if(param.getStatusCSR().equalsIgnoreCase("0"))
        {
                    logger.info("common_name: "+param.getCN());
                    logger.info("jobTitle: "+param.getTitle());
                    logger.info("mykad: "+param.getUid());
                    logger.info("mail_email: "+param.getEmail());
                    logger.info("locality: "+param.getLocality());
                    logger.info("state: "+param.getState());
                    logger.info("country: "+param.getCountry());
                    logger.info("corp_company: "+param.getCompany());
            
                    HashMap <String,String> sampleInput = new HashMap<String,String>();
                    sampleInput.put("common_name", param.getCN());
                    sampleInput.put("jobTitle", param.getTitle());
                    sampleInput.put("mykad", param.getUid());
                    sampleInput.put("mail_email", param.getEmail()); 
                    sampleInput.put("locality", param.getLocality()); 
                    sampleInput.put("state", param.getState());
                    sampleInput.put("country", param.getCountry());
                    sampleInput.put("corp_company", param.getCompany());
                    sampleInput.put("publish_flag", "yes"); 
                    //sampleInput.put("additional_field4",id_no);

                    SampleParameters.sampleInput = sampleInput;
                    param.setCertFileName(param.getUid());
                    param.setPinCert(PIN);
                    param.setCertValidity(certValidity);
                    param.setCsr(CSR);
        }else{
            logger.error("readCSR error: "+param.getErrorMsg());
            returnData.setiErrorCode("662");
            returnData.setsErrorMessage("Exception: "+param.getErrorMsg());
            return returnData;
        }
    
    
     param.setBase64Cert(base64);
    
     x509 cx509 = new x509();
        boolean getCertDet = false;
        //add readconfig 
                    try {
                        //convert p7b base64 to x509 base64 get serialnumber and validity date
                        getCertDet = cx509.convertb64(param);
                    } catch (IOException ex) {
                        returnData.setiErrorCode("622");
                        returnData.setsErrorMessage("Error: get cert details failed");
                        logger.error("[getCertDet] get cert details failed : " + ex.getMessage());
                        return returnData;
                    }

                    if(getCertDet) {
                        logger.info("[getCertDet] get cert details success");

                    } else {
                        returnData.setiErrorCode("623");
                        logger.error("[getCertDet] get cert details failed : ");
                        returnData.setsErrorMessage("Error: get cert details failed");
                    return returnData; //exit
                    }
    
                    String DN = param.getSubjDN();
                    
                        //get CN from subjectDN
                        String IDN[]=DN.split(",");
                        String IDN_child []=null;
                        String strToFind="CN";
                        String cnname=null;

                        for (int i = 0; i < IDN.length; i++) {
                            IDN_child=IDN[i].split("=");                  
                                //compare text
                                if (IDN_child[0].trim().compareTo(strToFind)==0){
                                    cnname=IDN_child[1];
                                    break;
                                }
                         }
                        System.out.println("cnname renewal "+cnname);
                        
                        //get email from subjectDN
                        String IDN_child1 []=null;
                        String strToFind1="EMAILADDRESS";
                        String email=null;

                        for (int i = 0; i < IDN.length; i++) {
                            IDN_child1=IDN[i].split("=");                  
                                //compare text
                                if (IDN_child1[0].trim().compareTo(strToFind1)==0){
                                    email=IDN_child1[1];
                                    break;
                                }
                         }
                        System.out.println("email renewal "+email);
                    

                Date d1 = null;
		Date d2 = null; 
                int validity = 0;
    
                DateFormat df = new SimpleDateFormat("dd/MM/yy HH:mm:ss");
                Calendar calobj = Calendar.getInstance();
                String currentDate = df.format(calobj.getTime());
                System.out.println("Current time: "+df.format(calobj.getTime()));       
                
		String endDate = param.getCertStartDate();
                
                try {
                        d1 = df.parse(endDate);
			d2 = df.parse(currentDate);

			//in milliseconds
			long diff = d2.getTime() - d1.getTime();

			long diffSeconds = diff / 1000 % 60;
			long diffMinutes = diff / (60 * 1000) % 60;
			long diffHours = diff / (60 * 60 * 1000) % 24;
			long diffDays = diff / (24 * 60 * 60 * 1000);

                        validity = (int)diffDays;
                        
			System.out.print(diffDays + " days, ");
			System.out.print(diffHours + " hours, ");
			System.out.print(diffMinutes + " minutes, ");
			System.out.print(diffSeconds + " seconds.");
               
                    } catch (Exception e) {
			e.printStackTrace();
		}
                
                System.out.println("validity "+validity);
                
                
                System.out.println();
      

        int extendValidity = validity + 365;// kene calculate balance cert + 365hari
        System.out.println("extendValidity "+extendValidity);
//        String validity = Integer.toString(extendValidity);
//        param.setCertValidity(validity);
        
            String certIssuer = param.getIssuerDN();//old cert issuer to revoke
            String serialnumberCert = param.getCertSerial();//old cert serialnumber to revoke
            
            System.out.println("certIssuer" +certIssuer);
            System.out.println("serialnumberCert" +serialnumberCert);
        //revoke first
        SampleCertMgmtClient  sampleCertMgmtClient = new SampleCertMgmtClient();
            //revoke old cert
            try {
			int result = sampleCertMgmtClient.revokeCertificate(serialnumberCert,CertificateManagementServiceStub.RevokeReasonCodeEnum.KeyCompromise,certIssuer); //TODO: you need to change SampleParameters.sampleCertSerial to suite your case
			if(result != 0) {
				System.out.println("ERROR: certificate is not revoked\n");
			}
                                          

		} catch (AxisFault a) {
			System.out.println("ERROR CODE : " + a.getFaultCode());
                        
                        returnData.setsErrorMessage("Exception failed: "+a.getFaultCode());
                        return returnData;
                        
		} catch (RemoteException e) {
			// TODO Auto-generated catch block

                        returnData.setiErrorCode("611");
                        returnData.setsErrorMessage("Exception failed: ");
                        return returnData;
		}



        boolean stat_getRenew=false;
    
        try {
        
        //get enrollment policy
        SamplePolicyServiceClient samplePolicyServiceClient = SamplePolicyServiceClient.getInstance(param);
        //samplePolicyServiceClient.param = param;
        //use the first enrollment policy to enroll for a cert
        PolicyServiceStub.CertificateEnrollmentPolicy certificateEnrollmentPolicy = samplePolicyServiceClient.enrollmentPolices[0];
        
        //use SampleEnrollmentServiceClient to request for certificate
        SampleEnrollmentServiceClient sampleEnrollmentServiceClient = new SampleEnrollmentServiceClient(certificateEnrollmentPolicy,samplePolicyServiceClient.getOIDByReferenceID(certificateEnrollmentPolicy.getPolicyOIDReference()).getValue(),param.getSampleOutputPath() + "/" + param.getCertFileName(),param);
        VeriSignCertIssuingServiceStub.RequestSecurityTokenResponse requestSecurutyTokenResponse = sampleEnrollmentServiceClient.enrollForCertificate(REQUEST_TYPE_ISSUE.getValue(), null,extendValidity,param);
        sampleEnrollmentServiceClient.processRequestSecurityTokenResponse(requestSecurutyTokenResponse,param);
        


        
        stat_getRenew=true;
        } catch (CertificateException e) {
                e.printStackTrace();
        } catch (NoSuchProviderException e) {
                e.printStackTrace();
        } catch (Throwable e) {
                e.printStackTrace();
        }
      
        if(stat_getRenew) {
            logger.info("[getRenewal] Renewal success");
            returnData.setiErrorCode("000");
            returnData.setsErrorMessage("Renewal success");

             //return base64

             boolean convertB64 = false;
             //add readconfig 
                    try {
                        //convert p7b base64 to x509 base64 get serialnumber and validity date
                        convertB64 = cx509.convertb64(param);
                    } catch (IOException ex) {
                        returnData.setiErrorCode("622");
                        returnData.setsErrorMessage("Exception: convert base64 p7b to x509 failed");
                        logger.error("[convertB64] convert base64 p7b to x509 failed : " + ex.getMessage());
                        return returnData;
                    }

                    if(convertB64) {
                        logger.info("[convertB64] convert base64 p7b to x509 success");

                    } else {
                        returnData.setiErrorCode("602");
                        logger.error("[convertB64] convert base64 p7b to x509 failed : ");

                    return returnData; //exit
                    }
                    
                    //save information to DB
            saveUserDet sUd = new saveUserDet();
            boolean update_db=sUd.saveUserDets(cnname,param.getUid(),param.getBase64Cert(),param.getCertStartDate(),param.getCertEndDate(),param.getPinCert(),param.getCertSerial(),param.getIssuerDN());
            if(update_db)
            { 
               logger.info("[saveUserDet] save user details status : "+sUd.status_code+""+sUd.status_msg);
            } 
            else {
               returnData.setiErrorCode(sUd.status_code);
               returnData.setsErrorMessage(sUd.status_msg);
               logger.error("[saveUserDet] save user details failed : "+sUd.status_code+""+sUd.status_msg);
               return returnData; //exit
            }
                
            logger.info("[migrateCert] migrateCert success");
            returnData.setiErrorCode("000");
            returnData.setBase64(param.getBase64Cert());
            returnData.setCertSerialnumber(param.getCertSerial());
            returnData.setStartDate(param.getCertStartDate());
            returnData.setEndDate(param.getCertEndDate());
            returnData.setsErrorMessage("migrateCert success");
            
        } else {
            returnData.setiErrorCode("651");
            returnData.setsErrorMessage("Renewal failed");  
            logger.error("[getRenewal] Renewal failed : ");
   
            return returnData; //exit
           
        }  
        
        
        deleteFile delete = new deleteFile();
        
        String p7b = param.getSampleOutputPath()+""+param.getCertFileName();
        String pass = param.getSampleOutputPath()+""+param.getCertFileName()+".p12.password";
        String response = param.getSampleOutputPath()+""+"Response.xml";
        
        System.out.println("p7b "+p7b);
        System.out.println("pass "+pass);
        System.out.println("response "+response);
        
        //delete file p7b
        delete.deleteFile(p7b);
        //delete file password   
        delete.deleteFile(pass);
        //delete Response.xml
        delete.deleteFile(response);
        
        
        return returnData;
    }
    
    
      //-----------------------ValidateRenewalParam----------------------------------------
    private boolean ValidateRenewalParam (String CAPayload,String CSR,String base64,String OU) {

    boolean stat_Valid=true;
            
      try {
        String paramVal=null;
        String[] params = new String[] {"CAPayload","CSR","Cert","OU"};
          for (String prm:params) {
                            
              //get value 
              if (prm.equals("CAPayload")) {
                  paramVal=CAPayload;                            
                }
              if (prm.equals("CSR")) {
                  paramVal=CSR;                            
                }
              if (prm.equals("Cert")) {
                  paramVal=base64;                            
                }
              if (prm.equals("OU")) {
                  paramVal=OU;                            
                }
             
             
                //validate 
                if(paramVal == null || paramVal.trim().length()==0) {
                    statusCode="600";
                    statusMsg="Missing parameter value for " + prm;
                    stat_Valid=false;
                    break;
                }
            }               
          
               
      } catch(Exception e){
          statusCode = "600";
          statusMsg = e.getMessage();
          return false;
      }

      return stat_Valid;
           
  }
    
    
//-----------------------------revoke----------------------------------------------
    
    @WebMethod(operationName = "revoke")
    public CLCData Revoke(@WebParam(name = "CAPayload") String CAPayload, @WebParam(name = "Cert") String base64) throws Throwable 
    {
        
        CLCData returnData = new CLCData();
        parametersData param = new parametersData();
        
//        logger.info("<<< REVOKE:" + ICNumber +" >>>");
//        logger.info("[Revoke] Certificates Revocation starts - ICNumber: " + ICNumber);
        
    boolean stat_Valid=ValidateRevokeParam(CAPayload,base64);
    if(stat_Valid) {
        logger.info("[Revoke] Parameter validation true");
        
    } else {
        
        returnData.setiErrorCode(statusCode); 
        logger.info("[Revoke] Parameter validation false");
        
        returnData.setsErrorMessage(statusMsg); 
        logger.info("[Revoke] Parameter validation false");

        return returnData;
    }
        
    
     //verifyCAPayload
        try{
            
           verifyCAPayload verify = new verifyCAPayload(); 
           String type = "revoke";
           String CSR = null;
           param = verify.varifyCAPayload(CAPayload,type,CSR);
        }catch(Exception e)
        { 

                returnData.setiErrorCode(param.getStatuscodePayload());
                returnData.setsErrorMessage("Error: "+param.getStatusPayload());
                logger.error("ReadCSR error: "+e.getMessage());
                logger.error("ReadCSR error: "+param.getStatusPayload());
                return returnData;
        }
    
        if(param.getStatuscodePayload().equalsIgnoreCase("-1")||param.getStatuscodePayload().equalsIgnoreCase("-7")){
            
                returnData.setiErrorCode("661");
                returnData.setsErrorMessage("Error: "+param.getStatusPayload());
                return returnData;
            
        }
    
    
        
        
         param.setBase64Cert(base64);
    
     x509 cx509 = new x509();
        boolean getCertDet = false;
        //add readconfig 
                    try {
                        //convert p7b base64 to x509 base64 get serialnumber and validity date
                        getCertDet = cx509.convertb64(param);
                    } catch (IOException ex) {
                        returnData.setiErrorCode("622");
                        returnData.setsErrorMessage("Exception: get cert details failed");
                        logger.error("[getCertDet] get cert details failed : " + ex.getMessage());
                        return returnData;
                    }

                    if(getCertDet) {
                        logger.info("[getCertDet] get cert details success");

                    } else {
                        returnData.setiErrorCode("602");
                        logger.error("[getCertDet] get cert details failed : ");

                    return returnData; //exit
                    }

            String certIssuer = param.getIssuerDN();//old cert issuer to revoke
            String serialnumberCert = param.getCertSerial();//old cert serialnumber to revoke
            
            System.out.println("certIssuer" +certIssuer);
            System.out.println("serialnumberCert" +serialnumberCert);
            
         
        
        logger.info("[Revoke] certIssuer "+certIssuer);
        logger.info("[Revoke] serialnumberCert "+serialnumberCert);
        
        SampleCertMgmtClient  sampleCertMgmtClient = new SampleCertMgmtClient();
        

        
        boolean stat_getRenew=false;
        try {
			int result = sampleCertMgmtClient.revokeCertificate(serialnumberCert,CertificateManagementServiceStub.RevokeReasonCodeEnum.KeyCompromise,certIssuer); //TODO: you need to change SampleParameters.sampleCertSerial to suite your case
			if(result != 0) {
				logger.error("[Revoke] ERROR: certificate is not revoked\n");
			}
                                          

		} catch (AxisFault a) {
			logger.error("[Revoke] ERROR CODE : " + a.getFaultCode());
                        returnData.setiErrorCode("610");
                        returnData.setsErrorMessage("Exception failed: "+a.getFaultCode());
                        //return returnData;
                        
		} catch (RemoteException e) {
                        logger.error("[Revoke] ERROR CODE : " + e.getMessage());
                        returnData.setiErrorCode("611");
                        returnData.setsErrorMessage("Exception failed: " + e.getMessage());
                        //return returnData;
		}
        
        if(stat_getRenew) {
            
            returnData.setiErrorCode("641");
            returnData.setsErrorMessage("Revoke failed");  
            logger.error("[Revoke] Revoke failed : ");
            
            //return returnData; //exit
            
        } else {
            
           updateUserDet sUd = new updateUserDet();
           boolean update_db=sUd.saveUserDets(serialnumberCert,certIssuer); 
            if(update_db)
            { 
               logger.info("[Revoke] delete user details status : "+sUd.status_code+""+sUd.status_msg);
            } 
            else {
               returnData.setiErrorCode(sUd.status_code);
               returnData.setsErrorMessage(sUd.status_msg);
               logger.error("[Revoke] delete user details failed : "+sUd.status_code+""+sUd.status_msg);
               return returnData; //exit
            }
            
           logger.info("[Revoke] Revoke success");
           returnData.setiErrorCode("000");
           returnData.setsErrorMessage("Revoke success");

        } 
        
        return returnData;
    }
    
      //-----------------------ValidateRevokeParam----------------------------------------
    private boolean ValidateRevokeParam (String CAPayload, String base64) {
       
    boolean stat_Valid=true;
    logger.info("[ValidateRevokeParam] starts");
    
      try {
        String paramVal=null;
        String[] params = new String[] {"CAPayload", "Cert"};
          for (String prm:params) {
                            
              //get value 
              if (prm.equals("CAPayload")) {
                  paramVal=CAPayload;                            
                }
              if (prm.equals("Cert")) {
                  paramVal=base64;                            
                }
             
             
             
                //validate 
                if(paramVal == null || paramVal.trim().length()==0) {
                    statusCode="600";
                    statusMsg="Missing parameter value for " + prm;
                    stat_Valid=false;
                    break;
                }
            }               
          
               
      } catch(Exception e){
          statusCode = "600";
          statusMsg = e.getMessage();
          logger.error("[ValidateRevokeParam] Exception: " + e.getMessage() + " StatusCode:" + statusCode);
          return false;
      }

      return stat_Valid;
           
  }
    
    
}
