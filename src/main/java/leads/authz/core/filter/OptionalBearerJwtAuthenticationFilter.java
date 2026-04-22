package leads.authz.core.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In NONE security mode: does not reject requests (no 401). If an {@code Authorization: Bearer} token
 * is present, attempts to populate {@link SecurityContextHolder} with a {@link Jwt} so
 * {@code @AuthenticationPrincipal Jwt} works. Invalid or malformed tokens are ignored.
 */
public class OptionalBearerJwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final ObjectProvider<JwtDecoder> jwtDecoderProvider;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;

    public OptionalBearerJwtAuthenticationFilter(
            ObjectProvider<JwtDecoder> jwtDecoderProvider,
            JwtAuthenticationConverter jwtAuthenticationConverter) {
        this.jwtDecoderProvider = jwtDecoderProvider;
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        Jwt jwt = resolveJwt(header);

        if (jwt != null) {
            var authentication = jwtAuthenticationConverter.convert(jwt);
            if (authentication != null) {
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Try verified decode first when a {@link JwtDecoder} bean exists; otherwise or on failure,
     * parse JWT structure without signature verification (NONE mode only — not for enforcement).
     */
    private Jwt resolveJwt(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return null;
        }
        String token = authorizationHeader.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            return null;
        }

        JwtDecoder decoder = jwtDecoderProvider.getIfAvailable();
        if (decoder != null) {
            try {
                return decoder.decode(token);
            } catch (Exception ignored) {
                // Invalid token must not block the request; try lenient parse below.
            }
        }

        return parseJwtLenient(token);
    }

    private static Jwt parseJwtLenient(String tokenValue) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(tokenValue);
            Map<String, Object> headers = new LinkedHashMap<>(signedJWT.getHeader().toJSONObject());
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();
            Map<String, Object> claims = new LinkedHashMap<>();
            claimSet.getClaims().forEach(claims::put);

            Instant issuedAt = claimSet.getIssueTime() != null
                    ? claimSet.getIssueTime().toInstant()
                    : Instant.now();
            Instant expiresAt = claimSet.getExpirationTime() != null
                    ? claimSet.getExpirationTime().toInstant()
                    : issuedAt.plusSeconds(3600);

            return new Jwt(tokenValue, issuedAt, expiresAt, headers, claims);
        } catch (Exception e) {
            return null;
        }
    }
}
