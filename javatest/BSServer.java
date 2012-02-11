import java.net.*;
import java.io.*;
import java.util.*;

public class BSServer extends Thread {


  private int numThreads = 10;
  private ServerSocket server;
  private boolean verbose;
    
  public BSServer(int port, boolean _verbose) throws IOException 
  {
    this.server = new ServerSocket(port);
    verbose = _verbose;
  }

  public void run() 
  {
    for (int i = 0; i < numThreads; i++) 
    {
      Thread t = new Thread(new RequestProcessor(verbose));
      t.start();   
    }
    System.out.println("INFO: Accepting connections on port " + server.getLocalPort());
    while (true) 
    {
      try 
      {
        Socket request = server.accept();
        RequestProcessor.processRequest(request);
      }
      catch (IOException e) 
      { 
      }   
    }
  }
  
  public static void main(String[] args) 
  {
    int port;
    try 
    {
      port = Integer.parseInt(args[0]);
      if (port < 0 || port > 65535) 
        port = 1921;
    }  
    catch (Exception e) 
    {
      port = 1921;
    }  
    boolean _verbose = (args.length >= 2);
    
    try 
    {            
      BSServer bsserver = new BSServer(port, _verbose);
      bsserver.start();
    }
    catch (IOException e) 
    {
      System.out.println("ERROR: Server could not start because of an " + e.getClass());
      System.out.println(e);
    }
  }
}
