package com.fakrul.signet.fpx;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.sql.Connection;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringEscapeUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/*import model.bean.FPX;
import my.mpay.module.payment.FpxController;
import my.mpay.module.payment.PaymentAdaptor;
import util.connection.DBConnection;
import util.general.Logger;
import util.money.moneyFormatter;
import util.property.SystemProperty;
import util.property.custom.CLogsProperty;
*/

/**
 * Servlet implementation class FPXServlet
 */
public class FPXServlet2 extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
    /**
     * @see HttpServlet#HttpServlet()
     */
	
    public FPXServlet2() {
        super();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) {
		doPerform(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) {
		doPerform(request, response);
	}
	
	protected void doPerform(HttpServletRequest request, HttpServletResponse response) {
		Connection connDB = null;
		try {
				String destination = "";
				FPX ft = new FPX();
				String msg = "";
				String action = "twoDomain";
				if(request.getParameter("action") != null) {
					action = StringEscapeUtils.escapeHtml4(request.getParameter("action"));
				}else if(request.getAttribute("action")!= null){
					action = StringEscapeUtils.escapeHtml4(request.getAttribute("action").toString());
				}
				connDB = DBConnection.getConnection();
			
				if (action.equalsIgnoreCase("twoDomain")) {
					Logger.writeActivity("*****************************Two domain FPX calling****************************", CLogsProperty.ADMINMEMBERSHIPLOG);
					
					destination = "fpx2domain.jsp";
					
					// TODO: get all incoming parameters
					String fpxMsgType = StringEscapeUtils.escapeHtml4(request.getParameter("fpx_msgType"))==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_msgType"));
					String fpxBankId = StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerBankId"))==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerBankId"));
					String fpxBankName = StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerBankName"))==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerBankName"));
					
					String amount = StringEscapeUtils.escapeHtml4(request.getParameter("amount"))==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("amount"));
					
					String step2 =  StringEscapeUtils.escapeHtml4(request.getParameter("step2"))==null?"1":StringEscapeUtils.escapeHtml4(request.getParameter("step2"));
					
					String email = StringEscapeUtils.escapeHtml4(request.getParameter("email"))==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("email")).trim();
					
					
					//check if confirmation has bee done
					if( step2.equalsIgnoreCase("0")){
						
						ft = processFPX(connDB, ft, moneyFormatter.centTOrm(amount), fpxMsgType,  fpxBankId,  fpxBankName,  email);
					
						//send form to fpx
						request.setAttribute("ft", ft);
						ft.LogFPX();
						destination = "sendFPXrequest.jsp";
					} else {
						request.setAttribute("reload_amt", "100");
						request.setAttribute("currentBal", "");
					}
							
				}else if(action.equalsIgnoreCase("direct")) {
							
						//if FPX call this transaction the transaction is successful(no approval code of any kind)
						//get response
						
						ft = new FPX();
						ft = getResponseFromFpx(request, ft);
						
						String msg_Type = "";
						//get needed field from respond
						msg_Type = ft.getFpx_msgType();
						
						
						
						if(ft.getPki_verification().equalsIgnoreCase("00"))
						{
							if(ft.getFpx_debitAuthCode().equals("00"))
							{
								if(msg_Type.equalsIgnoreCase("AC"))
								{
									//transaction successful
	
								}
								else
								{
									//wrong message type
								}
							}
							else if(ft.getFpx_debitAuthCode().equals("99"))
							{
								//PENDING AUTHORIZATION B2B1
								
								//transaction pending
							}
							else
							{
								//transaction failed
							}
						}
						else
						{
							//pki verification failed
						}
						
						
						request.setAttribute("msg", msg);
						request.setAttribute("ft", ft);
						destination = "sendFPXackAR.jsp";
						
						
					}else if(action.equalsIgnoreCase("indirect")) {
							ft = new FPX();
							ft = getResponseFromFpx(request, ft);
							
							
							
							if (ft.getFpx_debitAuthCode().equals("00"))
							{
								//reload success
							}
							else if (ft.getFpx_debitAuthCode().equals("99"))
							{
								//pending authorization
								
							}
							else
							{
								//transaction failed
							}
							
							request.setAttribute("ft", ft);
							destination = "indirectACmsg.jsp";
						}
						else if(action.equalsIgnoreCase("requestTrxStatus")) {
							
							Logger.writeActivity("requesting fpx transaction status status", CLogsProperty.GENERALLOG);
							String steps = request.getParameter("steps")==null||request.getParameter("steps").equals("")?"1":StringEscapeUtils.escapeHtml4(request.getParameter("steps"));
							
							if (steps.equals("1"))
							{
								Logger.writeActivity("fpx transaction status step one", CLogsProperty.GENERALLOG);
								destination = "/user/reload/fpx/fpx_txnStatus.jsp";
							}else
							{
								Logger.writeActivity("fpx transaction status step 2", CLogsProperty.GENERALLOG);
								ft = new FPX();
								String trx_id = request.getParameter("trx_id")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("trx_id"));
								ft = FpxController.getFpxReqParam(connDB, trx_id);
								ft.setFpx_msgType("AE");
								ft = FpxController.getFpxParam(connDB, ft);
								ft = FpxController.calCheckSum(ft);
								request.setAttribute("ft", ft);
								ft.LogFPX();
								destination = "sendFPXrequest.jsp";
								
							}
							
						} 
						else {
							destination = "/404error.jsp";
						}
					
			request.setAttribute("msg", msg);
			RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(destination);
			dispatcher.forward(request, response);
		} catch (Exception e) {
			e.printStackTrace();
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			Logger.writeError("FpxServlet:"+sw.toString(), CLogsProperty.MEMBERSHIPLOG);
		}finally {
			try {
				connDB.close();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	
	private static FPX getResponseFromFpx(HttpServletRequest request, FPX ft)
	{	
		ft.setFpx_buyerBankBranch(request.getParameter("fpx_buyerBankBranch")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerBankBranch")));
		ft.setFpx_buyerBankId(request.getParameter("fpx_buyerBankId")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerBankId")));
		ft.setFpx_buyerIban(request.getParameter("fpx_buyerIban")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerIban")));
		ft.setFpx_buyerId(request.getParameter("fpx_buyerId")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerId")));
		ft.setFpx_buyerName(request.getParameter("fpx_buyerName")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_buyerName")));
		ft.setFpx_creditAuthCode(request.getParameter("fpx_creditAuthCode")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_creditAuthCode")));
		ft.setFpx_creditAuthNo(request.getParameter("fpx_creditAuthNo")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_creditAuthNo")));
		ft.setFpx_debitAuthCode(request.getParameter("fpx_debitAuthCode")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_debitAuthCode")));
		ft.setFpx_debitAuthNo(request.getParameter("fpx_debitAuthNo")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_debitAuthNo")));
		ft.setFpx_fpxTxnId(request.getParameter("fpx_fpxTxnId")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_fpxTxnId")));
		ft.setFpx_fpxTxnTime(request.getParameter("fpx_fpxTxnTime")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_fpxTxnTime")));
		ft.setFpx_makerName(request.getParameter("fpx_makerName")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_makerName")));
		ft.setFpx_msgToken(request.getParameter("fpx_msgToken")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_msgToken")));
		ft.setFpx_msgType(request.getParameter("fpx_msgType")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_msgType")));
		ft.setFpx_sellerExId(request.getParameter("fpx_sellerExId")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_sellerExId")));
		ft.setFpx_sellerExOrderNo(request.getParameter("fpx_sellerExOrderNo")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_sellerExOrderNo")));
		ft.setFpx_sellerId(request.getParameter("fpx_sellerId")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_sellerId")));
		ft.setFpx_sellerOrderNo(request.getParameter("fpx_sellerOrderNo")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_sellerOrderNo")));
		ft.setFpx_sellerTxnTime(request.getParameter("fpx_sellerTxnTime")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_sellerTxnTime")));
		ft.setFpx_txnAmount(request.getParameter("fpx_txnAmount")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_txnAmount")));
		ft.setFpx_txnCurrency(request.getParameter("fpx_txnCurrency")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_txnCurrency")));
		ft.setFpx_checkSum(request.getParameter("fpx_checkSum")==null?"":StringEscapeUtils.escapeHtml4(request.getParameter("fpx_checkSum")));
		 
		try {
			ft.setPki_verification(FpxController.verifyCheckSum(ft));
			if(ft.getPki_verification().equals("00")){
				ft.setStatusDesc(FpxController.getResponseCodeDesc(null, ft.getFpx_debitAuthCode()));
			} else {
				ft.setStatusDesc("PKI Verification has failed. Payment failed.");
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | IOException e) {
			e.printStackTrace();
			Logger.writeError("FPXServlet:getResponseFromFpx():"+e.toString(), CLogsProperty.MEMBERSHIPLOG);
		}
		return ft;
	}
	

	// p.s. parameter fpxMsgType is fpxMsgToken
	public static FPX processFPX(Connection connDB, FPX ft, String trx_amt, String fpxMsgType, String fpxBankId, String fpxBankName, String email) throws Exception
	{	
		int reloadType = 1;//FPX
		String trxType = "2";//FPX
		PaymentAdaptor adaptor = new PaymentAdaptor();
		try {
			
			//create transaction data
			String trx_id = "0";
			
			ft.setFpx_msgType("AR");
			ft.setFpx_sellerTxnTime(new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()));
			ft.setFpx_sellerOrderNo(trx_id);
			ft.setFpx_sellerExOrderNo(trx_id);
			ft.setFpx_txnAmount(trx_amt);
			ft.setFpx_productDesc(" FPX Transaction @"+trx_id/*+" Amt RM"+ reload_amt*/);
			ft.setFpx_buyerEmail(email);
			ft = getTwoDomainFpxParam(ft);
			if(fpxMsgType.equalsIgnoreCase("01")) {
				ft.setFpx_msgToken("01");
			} else {
				ft.setFpx_msgToken("02");
			}
			ft.setFpx_buyerBankId(fpxBankId);
			ft.setFpx_buyerName(fpxBankName);
			ft.setFpx_sourceType("0");
			ft = FpxController.calCheckSum(ft);				
			
		} catch (Exception e) {
			e.printStackTrace();
			Logger.writeError("FPXServlet:processFPX():", CLogsProperty.MEMBERSHIPLOG);
		}
		return ft;
	}
	
	public static FPX getTwoDomainFpxParam(FPX ft) 
	{
		ft.setFpx_sellerExId("");
		ft.setFpx_sellerId("");
		ft.setFpx_sellerBankCode("");
		ft.setFpx_txnCurrency("");
		ft.setFpx_version("");
		if (ft.getFpx_msgType().equalsIgnoreCase("AE"))
		{
			ft.setUrl("");
		}
		else
		{
			ft.setUrl("");
		}
		return ft;
	}
	
	public static FPX calCheckSum(FPX ft) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException
	{
		//use key
		try{
			String fpx_checkSum = ft.getFpx_buyerAccNo()+"|"+ft.getFpx_buyerBankBranch()+"|"+ft.getFpx_buyerBankId()+"|"+ft.getFpx_buyerEmail()+"|"+ft.getFpx_buyerIban()+"|"+ft.getFpx_buyerId()+"|"+ft.getFpx_buyerName()+"|";
			fpx_checkSum += ft.getFpx_makerName()+"|"+ft.getFpx_msgToken()+"|"+ft.getFpx_msgType()+"|"+ft.getFpx_productDesc()+"|"+ft.getFpx_sellerBankCode()+"|"+ft.getFpx_sellerExId()+"|";
			fpx_checkSum += ft.getFpx_sellerExOrderNo()+"|"+ft.getFpx_sellerId()+"|"+ft.getFpx_sellerOrderNo()+"|"+ft.getFpx_sellerTxnTime()+"|"+ft.getFpx_txnAmount()+"|"+ft.getFpx_txnCurrency()+"|"+ft.getFpx_version();
			ft.setFpx_checkSum(fpx_checkSum);
			ft.setFinal_checkSum(signData(SystemProperty.FPX_KEY, fpx_checkSum, "SHA1withRSA"));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ft;
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
	
	
	
	

	

}
