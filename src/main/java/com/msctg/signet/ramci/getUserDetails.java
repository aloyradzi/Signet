/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.msctg.signet.ramci;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 *
 * @author NB035-17
 */
public class getUserDetails {
    
    String status_code=null;
    String status_msg=null;
    String UserId;

    public String getUserId() {
        return UserId;
    }

    public void setUserId(String UserId) {
        this.UserId = UserId;
    }

    public String getIc() {
        return Ic;
    }

    public void setIc(String Ic) {
        this.Ic = Ic;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getFullName() {
        return FullName;
    }

    public void setFullName(String FullName) {
        this.FullName = FullName;
    }
    String Ic;
    String phone;
    String FullName; 

    public String getStatus_code() {
        return status_code;
    }

    public void setStatus_code(String status_code) {
        this.status_code = status_code;
    }

    public String getStatus_msg() {
        return status_msg;
    }

    public void setStatus_msg(String status_msg) {
        this.status_msg = status_msg;
    }
    
    public boolean getUserDetails(String userID) {
    

    //MpkiData param = new MpkiData();
    returnData param = new returnData();

    //logger.info("[getUserDets] ICNumber: " + icnumber);
    
        
    boolean stat=true;
    status_code="";
    status_msg="";
    
   
    

    // JDBC driver name and database URL
    String JDBC_DRIVER = "com.mysql.jdbc.Driver";  

    String DB_URL = "jdbc:mysql://localhost:3306/datasuci";

    // Database credentials
    String USER = "root";
    String PASS = "";

    Connection conn = null;
    Statement stmt = null;
    
    
    try{
      //STEP 2: Register JDBC driver
      Class.forName("com.mysql.jdbc.Driver");

      //STEP 3: Open a connection
      //System.out.println("Connecting to database...");
      conn = DriverManager.getConnection(DB_URL,USER,PASS);

      
      //STEP 4: Execute a query
      //System.out.println("Creating statement...");
      stmt = conn.createStatement();

      //use count to check if record exist      
      String sqlCount;
      String sqlRec;
      
      String sqlCount2;
      String sqlRec2;
      
                   
             
              String sqlSelect;
                sqlSelect = "SELECT * FROM personal_info inner join mobilephone on personal_info.UserId = mobilephone.UserId where personal_info.Ic = "+userID;
   
                ResultSet rsCount = stmt.executeQuery(sqlSelect);

                //STEP 5: Extract data from result set
                  while(rsCount.next()){
                    //Retrieve by column name
                    //Retrieve by column name
                     UserId = rsCount.getString("UserId");
                     Ic = rsCount.getString("Ic");
                     phone = rsCount.getString("MobilePhone");
                     FullName = rsCount.getString("FullName");
                  } //while
                  rsCount.close();
                   
               
              if (UserId == null)
              {
                status_code = "642";
                status_msg = "User not found";

                

                return false;
              }
              else
              {
                  System.out.println("User found");
              }
                  
          stmt.close();
          conn.close();
       }catch(SQLException se){
          //Handle errors for JDBC
          StringWriter sw = new StringWriter();
          se.printStackTrace(new PrintWriter(sw));
          String exceptionAsString = sw.toString();
       
          status_code = "610";
          status_msg = "SQLException: " + se.getMessage();

          return false;
          
       }catch(Exception e){
          //Handle errors for Class.forName
           StringWriter sw = new StringWriter();
           e.printStackTrace(new PrintWriter(sw));
           String exceptionAsString = sw.toString();
            
          status_code = "602";
          status_msg = "Exception: " + e.getMessage();

          return false;
          
       }finally{
          //finally block used to close resources
          try{
             if(stmt!=null)
                stmt.close();
          }catch(SQLException se2){
          }// nothing we can do
          try{
             if(conn!=null)
                conn.close();
          }catch(SQLException se){
            StringWriter sw = new StringWriter();
            se.printStackTrace(new PrintWriter(sw));
            String exceptionAsString = sw.toString();
            
            status_code = "603";
            status_msg = "SQLException: " + se.getMessage();

            return false;
          }//end finally try
       }
      
      //return
       return stat;
      
  }
    
    
}
