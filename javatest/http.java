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

    int len = args[1].length() + 4;
    len = Integer.reverseBytes(len);
    try 
    {
      Socket skt = new Socket(args[0], 1922);
      BufferedReader in = new BufferedReader(new InputStreamReader(skt.getInputStream()));
      DataOutputStream out = new DataOutputStream(skt.getOutputStream());
      System.out.println("Sending url...");
      out.writeInt(len);
      out.writeBytes(args[1]);
      System.out.print("Received string: '");
      while (!in.ready()) 
      {}
      System.out.print(in.readLine()); // Read one line and output it
      System.out.println("'\n");
      in.close();
    }
    catch(Exception e) 
    {
      System.out.print(e.getMessage());
    }
  }
}
