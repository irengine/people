import java.lang.*;
import java.io.*;
import java.net.*;
import java.util.*;

class http2 
{
  public static void main(String args[]) 
  {
//    System.out.println(Integer.toHexString(i));  
    if (args.length != 9)
    {
      System.out.print("usage: http2 host acode_start acode_count ftype fdir findex adir= aindex= type\n");
      //                             0    1           2           3     4    5      6     7       8
      return;
    } 
    
    long acode_start, acode_count;
    
    try
    {
      acode_start = Long.valueOf(args[1]);
      acode_count = Long.valueOf(args[2]);
    }
    catch (NumberFormatException e)
    {
      System.out.println(e.getMessage());
      return;
    }
    
    if (acode_count <= 0)
    {
      System.out.println("acode_count <= 0, nothing to do");
      return;
    }
    
    StringBuffer buffer = new StringBuffer();
    buffer.append("http://127.0.0.1:10092/file?acode=");
    for (long i = 0; i < acode_count; ++ i)
    {
      buffer.append(Long.toString(acode_start + i));
      if (i != acode_count - 1)
        buffer.append(";");
    }
    
    buffer.append("&ftype=");
    buffer.append(args[3]);
    buffer.append("&fdir=");
    buffer.append(args[4]);
    buffer.append("&findex=");
    buffer.append(args[5]);
    buffer.append("&");

    buffer.append("adir=");    
    if (args[6].length() > 5)
    {
      String adir = args[6].substring(5, args[6].length());
		  for (long i = 0; i < acode_count; ++ i)
		  {
		    buffer.append(adir);
		    if (i != acode_count - 1)
		      buffer.append(";");
		  }
    }
    
    buffer.append("&");
    buffer.append(args[7]);
    buffer.append("&ver=");
    buffer.append(UUID.randomUUID().toString().replaceAll("-", ""));
    buffer.append("&type=");
    buffer.append(args[8]);    
    
    String request = buffer.toString();
    System.out.println("request = [" + request + "]");
    
    byte[] utf8Bytes = null;  
    try
    {
      utf8Bytes = request.getBytes("UTF8");
    } catch ( UnsupportedEncodingException e)
    {
      System.out.print(e.getMessage());
    }
    
    int len = utf8Bytes.length + 4;  
    System.out.println("send out packet length = " + len);
        //int len = args[1].length() + 4;
    len = Integer.reverseBytes(len);
    try 
    {
      Socket skt = new Socket(args[0], 1922);
      BufferedReader in = new BufferedReader(new InputStreamReader(skt.getInputStream()));
      DataOutputStream out = new DataOutputStream(skt.getOutputStream());
      System.out.println("Sending url...");
      out.writeInt(len);
      //out.writeUTF(args[1]); 
      //out.writeBytes(args[1]);
      out.write(utf8Bytes, 0, utf8Bytes.length);
      out.flush();
      System.out.print("Received string: '");
      while (!in.ready()) 
      {}
      System.out.print(in.readLine()); // Read one line and output it
      System.out.println("'\n");
      in.close();
    }
    catch(Exception e) 
    {
      System.out.println(e.getMessage());
    }
  }
}
