/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.msctg.signet.registration;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.JSONException;
import org.json.JSONObject;

/**
 *
 * @author NB033-17
 */
public class signetUser extends HttpServlet {

    private String KEY_PATH;
    private String JDBC_DRIVER;
    private String DB_URL;
    private String DBNAME;
    private String USER;
    private String PASS;
    
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
    }

    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
       // processRequest(request, response);

       
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream stream = classLoader.getResourceAsStream("WEB-INF/fpx.properties"); 
        Properties p = new Properties();
        
        
        
        KEY_PATH=null;
        JDBC_DRIVER=null;
        DB_URL=null;
        DBNAME=null;
        USER=null;
        PASS=null;
        
        if (stream == null) {
            
            // File not nound
            System.out.println("[validateServerProperties] Error 102:Can't locate fpx.properties");            
            throw new ServletException("Error 102: Can't locate fpx.properties");

        } else {  
            
            System.out.println("[validateServerProperties] Servlet prop file - fpx.properties found");
            p.load(stream);
            KEY_PATH = p.getProperty("key.path").trim();
            System.out.println("[validateServerProperties] key.path=" + KEY_PATH);
            JDBC_DRIVER = p.getProperty("JDBC_DRIVER").trim();
            System.out.println("[validateServerProperties] JDBC_DRIVER=" + JDBC_DRIVER);
            DB_URL = p.getProperty("DB_URL").trim();
            System.out.println("[validateServerProperties] DB_URL=" + DB_URL);
            DBNAME = p.getProperty("DBNAME").trim();
            System.out.println("[validateServerProperties] DBNAME=" + DBNAME);
            USER = p.getProperty("USER").trim();
            System.out.println("[validateServerProperties] USER=" + USER);
            PASS = p.getProperty("PASS").trim();
            System.out.println("[validateServerProperties] PASS=" + PASS);
            
        }
        
       
        try {
                
                String name = request.getParameter("name");
                String nationality = request.getParameter("nationality");
                String email = request.getParameter("email");
                String mobileno = request.getParameter("mobileno");
                String userid = request.getParameter("userid");
                String password = request.getParameter("password");
                String idImgFileName = request.getParameter("idImgFileName");
        
                response.setContentType("application/json");
                JSONObject obj = new JSONObject();
                
                
                if(name == null || name.trim().equals("")){
                obj.put("status", "Parameters (name) can't be empty.");
                }else if (nationality == null || nationality.equals("")){
                obj.put("status", "Parameters (nationality) can't be empty.");
                }else if (email == null || email.equals("")){
                obj.put("status", "Parameters (email) can't be empty.");
                }else if (mobileno == null || mobileno.equals("")){
                obj.put("status", "Parameters (mobileno) can't be empty.");
                }else if (userid == null || userid.equals("")){
                obj.put("status", "Parameters (userid) can't be empty.");
                }else if (password == null || password.equals("")){
                obj.put("status", "Parameters (password) can't be empty.");
                }else if (idImgFileName == null || idImgFileName.equals("")){
                obj.put("status", "Parameters (idImgFileName) can't be empty.");
                }
                
                try{
                    Class.forName(JDBC_DRIVER).newInstance();
                    // Open a connection
                    Connection conn = DriverManager.getConnection(DB_URL+DBNAME,USER,PASS);
                    // Execute SQL query
                    Statement stmt = conn.createStatement();
                    String sql;
                    sql = "INSERT INTO 'signet_user'(name,nationality,email,mobileno,userid,password,idImgFileName) "
                            + "values("+name+","+nationality+","+email+","+mobileno+","+userid+","+password+","+idImgFileName+")";
                    ResultSet rs = stmt.executeQuery(sql);
                    
                    rs.close();
                    stmt.close();
                    conn.close();
                    
                }catch(Exception e){
                    e.printStackTrace();
                }
                
                PrintWriter out = response.getWriter();
                out.println(obj);
                
            } catch (JSONException ex) {
                Logger.getLogger(ServletPOST.class.getName()).log(Level.SEVERE, null, ex);
            }
    }

    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
