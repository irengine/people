import java.lang.*;
import java.io.*;
import java.net.*;

class http 
{
  public static void main(String args[]) 
  {
//    System.out.println(Integer.toHexString(i));  
    if (args.length != 2)
    {
      System.out.print("usage: http host url\n");
      return;
    } 
    byte[] utf8Bytes = null;  
    try
    {
      utf8Bytes = args[1].getBytes("UTF8");
    } catch ( UnsupportedEncodingException e)
    {
      System.out.print(e.getMessage());
    }
      
    System.out.println("args[1].length = " + utf8Bytes.length);
    int len = utf8Bytes.length + 4;
    //int len = args[1].length() + 4;
    len = Integer.reverseBytes(len);
    try 
    {
      Socket skt = new Socket(args[0], 1922);
      //skt.setTcpNoDelay(true);
      DataInputStream in = new DataInputStream(skt.getInputStream());
      DataOutputStream out = new DataOutputStream(skt.getOutputStream());
      System.out.println("Sending url...");
      out.writeInt(len);
      //out.writeUTF(args[1]); 
      //out.writeBytes(args[1]);
      out.write(utf8Bytes, 0, utf8Bytes.length);
      out.flush();
//      out.close();
      System.out.print("Received string: '");
      byte b = in.readByte();
      System.out.print((char)b); // Read one line and output it
      System.out.println("'\n");
      in.close();
    }
    catch(Exception e) 
    {
      System.out.print(e.getMessage());
    }
  }
}
