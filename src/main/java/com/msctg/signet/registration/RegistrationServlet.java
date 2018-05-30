package com.msctg.signet.registration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

/*
import org.json.JSONObject;

import controller.auth.Authentication;
import util.connection.DBConnection;
import util.email.EmailController;
*/
@Path("account")
public class RegistrationServlet {
	@Path("registeracc")
	@POST
	@Produces(MediaType.TEXT_PLAIN)
	public Response registerAcc(@FormParam("name") String name, @FormParam("nationality") String nationality,
			@FormParam("idno") String idno, @FormParam("email") String email,
			@FormParam("mobileno") String mobileno, @FormParam("dob") String dob, @FormParam("userid") String loginid, @FormParam("agreementflag") String agreementFlag) {
		
		
		String cardno = "";
		String expirydate = "";
		String idtype = null;
		String addr1 = "";
		String addr2 = "";
		String stateid = null;
		String city = "";
		String postalcode = "";
		String imgid = null;
		String securephrase = "";
		String password = "";
		String maidenname = "";
		String idImgFileName = "";
		mobileno = mobileno.replace("+", "");
		
		String msg = "Failed";
		String status = "01";
		
		//input checking
		if(name == null || name.trim().equals("")){
			return Response.status(Status.BAD_REQUEST).entity("Parameters (name) can't be empty.").type(MediaType.TEXT_PLAIN).build();
		}
		
		if(nationality == null || nationality.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("Parameters (nationality) can't be empty.").type(MediaType.TEXT_PLAIN).build();
		}
		
		
		
		if(idno == null || idno.trim().equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("Parameters (idno) can't be empty.").type(MediaType.TEXT_PLAIN).build();
		}
		
		
		if(mobileno == null || mobileno.trim().equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("Parameters (mobileno) can't be empty.").type(MediaType.TEXT_PLAIN).build();
		}
		
		if(email == null || email.trim().equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("Parameters (email) can't be empty.").type(MediaType.TEXT_PLAIN).build();
		}
		
		if(dob == null || dob.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("Parameters (dob) can't be empty.").type(MediaType.TEXT_PLAIN).build();
		}
		
		
		try {
			Connection connDB = DBConnection.getConnection();
			connDB.setAutoCommit(false);
			
			name = name.trim();
			idno = idno.trim();
			email = email.trim();
			mobileno = mobileno.trim();
			loginid = loginid.trim();
			
			//check if user is registered
			
			String selectString = new StringBuffer("SELECT * FROM UserAccount WHERE ").toString();
			
			// Run the sql query
			PreparedStatement stmt = connDB.prepareStatement(selectString);
			stmt.setString(1, loginid);
			stmt.setString(2, email);
			stmt.setString(3, mobileno);
			stmt.setString(4, idtype);
			stmt.setString(5, idno);
			ResultSet rs = stmt.executeQuery();
			if(!rs.next())
			{
				//not registered.... will proceed with registration 
				String randomSalt = Authentication.getRandomSalt();
				String hashResult = Authentication.genHashResult(loginid, password, randomSalt);
				
				selectString = new StringBuffer("INSERT INTO UserAccount (usertypelookup_id, login_id, hash_result, salt, userstatuslookup_id, last_update_date, authimagelookup_id, login_phrase, mother_maiden_name, KYCStatusLookup_id, DocStatusLookup_id) " +
						"VALUES (?, ?, ?, ?, ?, GETDATE(), ?, ?, ?, ?, ?); SELECT SCOPE_IDENTITY();").toString();
	
				// Run the sql query
				stmt = connDB.prepareStatement(selectString);
				stmt.setInt(1, 1);
				stmt.setString(2, loginid);
				stmt.setString(3, hashResult);
				stmt.setString(4, randomSalt);
				stmt.setInt(5, 2); // active
				stmt.setString(6, imgid);
				stmt.setString(7, securephrase);
				stmt.setString(8, maidenname);
				stmt.setInt(9, 0); // new
				stmt.setInt(10, 0); // none
				rs = stmt.executeQuery();
				
				if(rs.next())
				{
					//send welcome email
					EmailController.sendWelcomeEmail(loginid);
					msg = "Registration Successful";
					status = "00";
				}
				else
				{
					status = "01";
					msg = "Registration failed. Please contact our admin for assistance.";
				}
			}else {
				status = "02";
				msg = "User registered previously.";
			}
			
			connDB.close();
			
			//form return object
			JSONObject return_obj = new JSONObject();
			return_obj.put("status", status);
			return_obj.put("msg", msg);
			
			return Response.status(Status.OK).entity(return_obj.toString()).type(MediaType.TEXT_PLAIN).build();
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("System Encountered an Error").type(MediaType.TEXT_PLAIN).build();
		}
		
	}
	
}
