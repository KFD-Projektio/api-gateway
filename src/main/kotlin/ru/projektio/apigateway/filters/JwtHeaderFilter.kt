package ru.projektio.apigateway.filters

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SecurityException
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.core.io.buffer.DataBufferUtils
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import ru.projektio.apigateway.config.JwtProperties
import ru.projektio.apigateway.exception.JwtAuthenticationException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

@Component
class JwtHeaderFilter(
    private val jwtProperties: JwtProperties
) : AbstractGatewayFilterFactory<JwtHeaderFilter.Config>(Config::class.java) {

    companion object {
        private val log = LoggerFactory.getLogger(JwtHeaderFilter::class.java)
        private const val BEARER_PREFIX = "Bearer "
    }

    class Config

    override fun apply(config: Config): GatewayFilter {
        return GatewayFilter { exchange, chain ->
            validateRequest(exchange)
                .flatMap { claims ->
                    chain.filter(withUserIdHeader(exchange, claims))
                }
                .onErrorResume { ex ->
                    handleAuthenticationError(exchange, ex)
                }
        }
    }

    private fun validateRequest(exchange: ServerWebExchange): Mono<Claims> {
        return Mono.fromCallable {
            val authHeader = getAuthorizationHeader(exchange)
            val jwt = extractJwtToken(authHeader)
            validateToken(jwt)
        }.subscribeOn(Schedulers.boundedElastic())
    }

    private fun getAuthorizationHeader(exchange: ServerWebExchange): String {
        return exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
            ?: throw JwtAuthenticationException("Authorization header is missing")
    }

    private fun extractJwtToken(authHeader: String): String {
        if (!authHeader.startsWith(BEARER_PREFIX)) {
            throw JwtAuthenticationException("Invalid authorization header format")
        }
        return authHeader.substring(BEARER_PREFIX.length).also {
            if (it.isBlank()) throw JwtAuthenticationException("Empty JWT token")
        }
    }

    private fun validateToken(jwt: String): Claims {
        return try {
            Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt)
                .payload
                .also { log.debug("Validated JWT for user: ${it.subject}") }
        } catch (ex: SecurityException) {
            throw JwtAuthenticationException("Invalid JWT signature: ${ex.message}")
        } catch (ex: Exception) {
            throw JwtAuthenticationException("JWT validation failed: ${ex.message}")
        }
    }

    private fun withUserIdHeader(
        exchange: ServerWebExchange,
        claims: Claims
    ): ServerWebExchange {
        val userId = claims.get("user_id", Long::class.java)
        ?: throw JwtAuthenticationException("User ID not found in JWT")

        val request = exchange.request.mutate()
            .header("X-User-ID", userId.toString())
            .build()

        return exchange.mutate().request(request).build().also {
            log.debug("Added X-User-ID header: $userId")
        }
    }

    private fun handleAuthenticationError(
        exchange: ServerWebExchange,
        ex: Throwable
    ): Mono<Void> {
        return when (ex) {
            is JwtAuthenticationException -> {
                log.warn("JWT authentication failed: ${ex.message}")
                exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                exchange.response.headers.add("WWW-Authenticate", "Bearer error=\"invalid_token\"")
            }
            else -> {
                log.error("Unexpected authentication error", ex)
                exchange.response.statusCode = HttpStatus.INTERNAL_SERVER_ERROR
            }
        }.run {
            val buffer = exchange.response.bufferFactory().wrap(ex.message?.toByteArray() ?: byteArrayOf())
            exchange.response.writeWith(Mono.just(buffer))
                .doOnCancel {
                    DataBufferUtils.release(buffer)
                }
        }
    }

    private val publicKey: PublicKey by lazy {
        try {
            val keyBytes = Base64.getDecoder().decode(jwtProperties.publicRsaFile.replace("\n", ""))
            val spec = X509EncodedKeySpec(keyBytes)
            KeyFactory.getInstance("RSA").generatePublic(spec).also {
                log.info("Successfully initialized RSA public key")
            }
        } catch (ex: IllegalArgumentException) {
            throw IllegalStateException("Invalid Base64 encoding for public key ${ex.message}", ex)
        } catch (ex: Exception) {
            throw IllegalStateException("Failed to initialize public key ${ex.message}", ex)
        }
    }
}