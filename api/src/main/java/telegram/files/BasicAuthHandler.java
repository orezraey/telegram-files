package telegram.files;

import cn.hutool.core.util.StrUtil;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BasicAuthHandler implements Handler<RoutingContext> {

    private static final Log log = LogFactory.get();
    private static final String BASIC_PREFIX = "Basic ";
    private static final String REALM = "Telegram Files";

    private final String expectedUsername;
    private final String expectedPassword;

    public BasicAuthHandler(String username, String password) {
        if (StrUtil.isBlank(username) || StrUtil.isBlank(password)) {
            throw new IllegalArgumentException("Username and password must not be blank");
        }
        this.expectedUsername = username;
        this.expectedPassword = password;
    }

    @Override
    public void handle(RoutingContext ctx) {
        String authHeader = ctx.request().getHeader("Authorization");

        if (isValidAuth(authHeader)) {
            ctx.next();
        } else {
            log.debug("Unauthorized access attempt from: " + ctx.request().remoteAddress());
            ctx.response()
                    .setStatusCode(401)
                    .putHeader("WWW-Authenticate", "Basic realm=\"" + REALM + "\"")
                    .end("Unauthorized");
        }
    }

    private boolean isValidAuth(String authHeader) {
        if (StrUtil.isBlank(authHeader)) {
            return false;
        }

        if (!authHeader.startsWith(BASIC_PREFIX)) {
            return false;
        }

        String base64Credentials = authHeader.substring(BASIC_PREFIX.length());
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(decodedBytes, StandardCharsets.UTF_8);
            String[] parts = credentials.split(":", 2);

            if (parts.length != 2) {
                return false;
            }

            String username = parts[0];
            String password = parts[1];

            return expectedUsername.equals(username) && expectedPassword.equals(password);
        } catch (IllegalArgumentException e) {
            log.debug("Failed to decode Authorization header: " + e.getMessage());
            return false;
        }
    }
}
