package com.kohlschutter.test.iaikbug;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URL;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.CompletableFuture;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import iaik.security.jsse.provider.IAIKJSSEProvider;
import iaik.security.provider.IAIK;

public class IAIKBugTest {
  private static SSLContext newSSLContext(String protocol, Provider provider) {
    try {
      SSLContext context;
      if (provider == null) {
        context = SSLContext.getInstance(protocol);
      } else {
        context = SSLContext.getInstance(protocol, provider);
      }

      // NOTE: Using the same keystore for simplicity only
      KeyStore ks = KeyStore.getInstance("PKCS12");

      URL url = IAIKBugTest.class.getResource("bug.p12");
      if (url == null) {
        throw new IllegalStateException("Missing expected resource: bug.p12 relative to "
            + IAIKBugTest.class);
      }

      try (InputStream in = url.openStream()) {
        ks.load(in, "password".toCharArray());
      }

      KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
          .getDefaultAlgorithm());
      kmf.init(ks, "password".toCharArray());

      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
          .getDefaultAlgorithm());
      tmf.init(ks);

      context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
      return context;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @ParameterizedTest(name = "useIAIK = {0}")
  @ValueSource(booleans = {false, true})
  public void testIAIKBug(boolean useIAIK) throws Exception {
    System.out.println("Running test with useIAIK=" + useIAIK);

    Provider jceProvider;
    Provider jsseProvider;
    if (useIAIK) {
      jceProvider = new IAIK();
      jsseProvider = new IAIKJSSEProvider();
      Security.addProvider(jceProvider);
      Security.addProvider(jsseProvider);
    } else {
      jceProvider = null;
      jsseProvider = null;
    }

    CompletableFuture<SocketAddress> serverAddress = new CompletableFuture<>();
    CompletableFuture<Throwable> serverFuture = CompletableFuture.supplyAsync(() -> {
      try {
        SSLSocketFactory serverSocketFactory = newSSLContext("TLS", jsseProvider)
            .getSocketFactory();

        try (ServerSocket serverSocket = new ServerSocket(0, 50, InetAddress
            .getLoopbackAddress())) {
          serverAddress.complete(serverSocket.getLocalSocketAddress());
          try (Socket socket = serverSocket.accept();
              SSLSocket sslSocket = (SSLSocket) serverSocketFactory.createSocket(socket,
                  "localhost.junixsocket", 0, false)) {

            sslSocket.setUseClientMode(false);

            sslSocket.startHandshake();
            try (InputStream in = sslSocket.getInputStream();
                OutputStream out = sslSocket.getOutputStream()) {

              int r = in.read();
              if (r != 'X') {
                throw new IllegalStateException("Expected X but got: " + ((r == -1) ? "nothing"
                    : (char) r));
              }
              out.write('Y');
            }
          }
        }
        return null;
      } catch (Throwable e) {
        e.printStackTrace();
        return e;
      }
    });

    try (Socket socket = new Socket()) {
      socket.connect(serverAddress.get());

      SSLSocketFactory clientSocketFactory = newSSLContext("TLS", jsseProvider).getSocketFactory();
      try (SSLSocket sslSocket = (SSLSocket) clientSocketFactory.createSocket(socket,
          "localhost.junixsocket", 0, false)) {

        sslSocket.setUseClientMode(true);

        sslSocket.startHandshake();
        try (InputStream in = sslSocket.getInputStream();
            OutputStream out = sslSocket.getOutputStream()) {
          out.write('X');
          int r = in.read();
          if (r != 'Y') {
            throw new IllegalStateException("Expected Y but got: " + ((r == -1) ? "nothing"
                : (char) r));
          }
        }
      }
    }

    if (serverFuture.get() == null) {
      System.out.println("Terminated successfully");
    }
  }
}
