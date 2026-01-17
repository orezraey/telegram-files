package telegram.files;

import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BasicAuthHandlerTest {

    private Vertx vertx;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
    }

    @AfterEach
    void tearDown() {
        vertx.close();
    }

    @Test
    void testConstructorThrowsOnBlankUsername() {
        assertThrows(IllegalArgumentException.class, () -> new BasicAuthHandler("", "password"));
    }

    @Test
    void testConstructorThrowsOnBlankPassword() {
        assertThrows(IllegalArgumentException.class, () -> new BasicAuthHandler("user", ""));
    }

    @Test
    void testValidCredentialsPassThrough() {
        BasicAuthHandler handler = new BasicAuthHandler("admin", "secret123");
        String validAuth = "Basic " + java.util.Base64.getEncoder().encodeToString("admin:secret123".getBytes());

        RoutingContext ctx = mock(RoutingContext.class);
        when(ctx.request()).thenReturn(mock(io.vertx.core.http.HttpServerRequest.class));
        when(ctx.request().getHeader("Authorization")).thenReturn(validAuth);

        handler.handle(ctx);

        verify(ctx).next();
        verify(ctx, never()).response();
    }

    @Test
    void testInvalidCredentialsReturns401() {
        BasicAuthHandler handler = new BasicAuthHandler("admin", "secret123");
        String invalidAuth = "Basic " + java.util.Base64.getEncoder().encodeToString("admin:wrong".getBytes());

        RoutingContext ctx = mock(RoutingContext.class);
        when(ctx.request()).thenReturn(mock(io.vertx.core.http.HttpServerRequest.class));
        when(ctx.request().getHeader("Authorization")).thenReturn(invalidAuth);
        when(ctx.request().remoteAddress()).thenReturn(io.vertx.core.net.SocketAddress.inetSocketAddress(0, "127.0.0.1"));

        io.vertx.core.http.HttpServerResponse response = mock(io.vertx.core.http.HttpServerResponse.class);
        when(ctx.response()).thenReturn(response);
        when(response.setStatusCode(401)).thenReturn(response);
        when(response.putHeader(anyString(), anyString())).thenReturn(response);

        handler.handle(ctx);

        verify(ctx, never()).next();
        verify(response).setStatusCode(401);
        verify(response).putHeader("WWW-Authenticate", "Basic realm=\"Telegram Files\"");
        verify(response).end("Unauthorized");
    }

    @Test
    void testMissingAuthHeaderReturns401() {
        BasicAuthHandler handler = new BasicAuthHandler("admin", "secret123");

        RoutingContext ctx = mock(RoutingContext.class);
        when(ctx.request()).thenReturn(mock(io.vertx.core.http.HttpServerRequest.class));
        when(ctx.request().getHeader("Authorization")).thenReturn(null);
        when(ctx.request().remoteAddress()).thenReturn(io.vertx.core.net.SocketAddress.inetSocketAddress(0, "127.0.0.1"));

        io.vertx.core.http.HttpServerResponse response = mock(io.vertx.core.http.HttpServerResponse.class);
        when(ctx.response()).thenReturn(response);
        when(response.setStatusCode(401)).thenReturn(response);
        when(response.putHeader(anyString(), anyString())).thenReturn(response);

        handler.handle(ctx);

        verify(ctx, never()).next();
        verify(response).setStatusCode(401);
    }

    @Test
    void testMalformedBase64Returns401() {
        BasicAuthHandler handler = new BasicAuthHandler("admin", "secret123");

        RoutingContext ctx = mock(RoutingContext.class);
        when(ctx.request()).thenReturn(mock(io.vertx.core.http.HttpServerRequest.class));
        when(ctx.request().getHeader("Authorization")).thenReturn("Basic not-valid-base64!@#");
        when(ctx.request().remoteAddress()).thenReturn(io.vertx.core.net.SocketAddress.inetSocketAddress(0, "127.0.0.1"));

        io.vertx.core.http.HttpServerResponse response = mock(io.vertx.core.http.HttpServerResponse.class);
        when(ctx.response()).thenReturn(response);
        when(response.setStatusCode(401)).thenReturn(response);
        when(response.putHeader(anyString(), anyString())).thenReturn(response);

        handler.handle(ctx);

        verify(ctx, never()).next();
        verify(response).setStatusCode(401);
    }
}
