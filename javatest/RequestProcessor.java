import java.net.*;
import java.io.*;
import java.util.*;
    
public class RequestProcessor implements Runnable 
{
  private static List pool = new LinkedList();
  private boolean verbose;
  
  public RequestProcessor(boolean _verbose) 
  {
    verbose = _verbose;
  }
  
  public static void processRequest(Socket request) 
  {
    synchronized (pool) 
    {
      pool.add(pool.size(), request);
      pool.notifyAll();
    }
  }  
  
  private boolean read_buff(Reader in, char [] buff)
  {
    int current_len = 0;
    int c;
    try
    {  
      while (true)
      {
        c = in.read(buff, current_len, buff.length - current_len);
        if (c == -1)
        {
          System.out.println("INFO: peer closed");
          return false;
        }  
        current_len += c;
        if (current_len == buff.length)
          return true;
		  }
    }
    catch (IOException e) 
    {
      System.out.println("ERROR: " + e.getMessage());
      return false;
    }    
  }
  
  private boolean read_packet(Reader in, StringBuffer result)
  {
    char[] header = new char[12];

    if (!read_buff(in, header))
      return false;
	  
    String slen = new String(header, 0, 8);
    int len;
    try
    {
      len = Integer.valueOf(slen);
    }
    catch (NumberFormatException e)
    {
      System.out.println("ERROR: bad packet header length number");
      return false;
    }
    
    if (len < header.length + 1)
    {
      System.out.println("ERROR: bad packet header length, too small " + len);
      return false;
    }
    
    String s_magic = new String(header, 8, 4);
    if (s_magic.compareTo("vc5X") != 0)
    {
      System.out.println("ERROR: bad header magic:" + s_magic);
      return false;
    }

    result.append(header);

    char buff[] = new char[len - header.length];
    if (!read_buff(in, buff))
	  {
	    System.out.println("ERROR: read packet body failed");
	    return false; 
	  } 
	  
	  if (buff[buff.length - 1] != '$')
	  {
	    System.out.println("ERROR: invalid buff tail mark:" + buff[buff.length - 1]);
	    return false;
	  }
	  
    result.append(buff);
    if (verbose)
      System.out.println("INFO: got a valid request: " + result);
    else
	  {
	    String s = new String(header, 0, header.length);
	    System.out.println("INFO: packet header:" + s);
    }        
    return true;
  }

  private boolean handle_request(StringBuffer request, Writer out)
  {
    return true;
  }

  public void run() 
  {
    while (true) 
    {       
      Socket connection;
      synchronized (pool) 
      {         
        while (pool.isEmpty()) 
        {
          try 
          {
            pool.wait();
          }
          catch (InterruptedException e) 
          {
          }
        }
        connection = (Socket) pool.remove(0); 
      }

      
      try 
      {            
        OutputStream raw = new BufferedOutputStream(connection.getOutputStream());         
        Writer out = new OutputStreamWriter(raw);
        Reader in = new InputStreamReader(new BufferedInputStream(connection.getInputStream()), "ASCII");
        while (true) 
        {
          StringBuffer request = new StringBuffer();
          if (!read_packet(in, request))
            break;
          if (!handle_request(request, out))
            break;
        }
      }
      catch (IOException e) {
      }
      finally 
      {
        try 
        {
          connection.close();        
        }
        catch (IOException e) {} 
      }
      
    } // end while

  } // end run


} // end RequestProcessor
